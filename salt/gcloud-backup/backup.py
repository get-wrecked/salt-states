#!/usr/bin/env -S uv run

# /// script
# dependencies = [
#     "google-cloud-storage",
# ]
# ///


import argparse
import base64
import contextlib
import grp
import hashlib
import json
import logging
import os
import pwd
import re
import secrets
import stat
import sys
from collections import namedtuple
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

from google.cloud import storage
from google.api_core.exceptions import BadRequest

TargetFile = namedtuple("TargetFile", "local_path remote_path md5_hash metadata action")
MANIFEST_REMOTE_PATH = ".manifest.json"


class BackupManager:
    def __init__(self, config_file: str, dry_run: bool = False, verbose: bool = False):
        self.logger = self._get_logger(verbose)
        self.dry_run = dry_run
        self.csek_key = None
        self.config = self._load_config(config_file)
        self.client = storage.Client()
        self.bucket = self.client.bucket(self.config["bucket_name"])
        self.found_uids = set()
        self.found_gids = set()
        self.manifest_data = {
            "uid_mapping": {},
            "gid_mapping": {},
            "directory_permissions": {},
        }

    def _get_logger(self, verbose: bool):
        logger = logging.getLogger(__name__)
        formatter = logging.Formatter("%(levelname)s: %(message)s")
        stdout = logging.StreamHandler(stream=sys.stdout)
        stdout.setLevel(logging.DEBUG if verbose else logging.INFO)
        # Only log debug/info to stdout, the rest to stderr only
        stdout.addFilter(lambda record: record.levelno < logging.WARNING)
        stderr = logging.StreamHandler()
        stderr.setLevel(logging.WARNING)
        stderr.setFormatter(formatter)
        logger.addHandler(stdout)
        logger.addHandler(stderr)
        logger.setLevel(logging.DEBUG)
        return logger

    def _load_config(self, config_file: str) -> dict:
        try:
            with open(config_file, "r") as f:
                config = json.load(f)

            required_keys = ["bucket_name", "targets"]
            for key in required_keys:
                if key not in config:
                    raise ValueError(f"Missing required config key: {key}")

            if "csek_key" in config:
                # CSEK key should be base64 encoded in config
                key_bytes = base64.b64decode(config["csek_key"])
                if not len(key_bytes) == 32:
                    raise ValueError("CSEK key must be 32 bytes when decoded")
                self.csek_key = key_bytes

            if "credentials_path" in config:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = config[
                    "credentials_path"
                ]

            return config
        except Exception as e:
            self.logger.error(f"Failed to load config file {config_file}: {e}")
            sys.exit(1)

    def run_backup(self):
        targets = self.config.get("targets", [])
        exclude_pattern = self.config.get("exclude")

        remote_objects = self._get_remote_objects()
        remote_objects = {blob.name: blob for blob in remote_objects}
        action_queue = self._scan_local_files(targets, exclude_pattern, remote_objects)

        # Any remote file that hasn't been compared yet doesn't exists locally anymore, remove
        for blob_name in remote_objects:
            action_queue.append(TargetFile(None, blob_name, None, None, "delete"))

        self._upload_files(action_queue)
        self._upload_manifest()

        if not action_queue:
            self.logger.info("Backup completed, no changes.")
        else:
            upload_count = sum(1 for f in action_queue if f.action == "upload")
            update_count = sum(1 for f in action_queue if f.action == "metadata")
            deleted_count = sum(1 for f in action_queue if f.action == "delete")
            self.logger.info(
                f"Backup completed. Uploaded: {upload_count}, updated metadata: {update_count}, deleted: {deleted_count}."
            )

    def run_restore(self, destination):
        manifest = self._get_manifest()
        self._load_validated_id_mappings(manifest)

        # Ensure destination exists
        with contextlib.suppress(FileExistsError):
            os.mkdir(destination)

        # Clear umask to ensure modes are restored correctly
        os.umask(0)

        self._restore_directories(manifest, destination)

        remote_objects = self._get_remote_objects()
        restore_count = 0
        for blob in remote_objects:
            self._restore_blob(destination, blob)
            restore_count += 1

        self._restore_directory_times(manifest, destination)

        self.logger.info(f"Restored {restore_count} files.")

    def _get_manifest(self):
        manifest_blob = self.bucket.blob(
            MANIFEST_REMOTE_PATH, encryption_key=self.csek_key
        )
        if not manifest_blob.exists():
            self.logger.error("No remote manifest, can't restore.")
            sys.exit(1)

        return json.loads(manifest_blob.download_as_text())

    def _load_validated_id_mappings(self, manifest):
        self.uid_mapping: Dict[int, int] = {}
        self.gid_mapping: Dict[int, int] = {}

        for uid, username in manifest.get("uid_mapping", {}).items():
            with contextlib.suppress(KeyError):
                self.uid_mapping[uid] = pwd.getpwnam(username).pw_uid

        for gid, groupname in manifest.get("gid_mapping", {}).items():
            with contextlib.suppress(KeyError):
                self.gid_mapping[gid] = grp.getgrnam(groupname).gr_gid

    def _restore_directories(self, manifest, destination):
        # Sort directories by nesting level to ensure we create parents first
        # to ensure we can set the mode on creation
        sorted_directories = sorted(
            manifest["directory_permissions"].items(),
            key=lambda t: len(t[0].split("/")),
        )
        for directory, target_stat in sorted_directories:
            directory_path = os.path.join(destination, directory)
            target_mode = int(target_stat["mode"], base=8)
            target_uid = self.uid_mapping.get(target_stat["uid"])
            target_gid = self.gid_mapping.get(target_stat["gid"])
            if target_uid is None or target_gid is None:
                self.logger.error(
                    "Attempted restoration of directory %s with unknown uid or gid on the target system",
                    directory,
                )
                sys.exit(1)
            try:
                os.mkdir(directory_path, mode=target_mode)
            except FileExistsError:
                dir_stat = os.stat(directory_path)
                current_mode = stat.S_IMODE(dir_stat.st_mode)
                if current_mode != target_mode:
                    self.logger.info(
                        f"Directory {directory_path} already existed with different mode "
                        f"{current_mode:o}, changing to {target_stat['mode']}."
                    )
                    os.chmod(directory_path, target_mode)

                if dir_stat.st_uid != target_uid or dir_stat.st_gid != target_gid:
                    self.logger.info(
                        f"Directory {directory_path} already existed with different permissions "
                        f"{dir_stat.st_uid}:{dir_stat.st_gid}, changing to {target_uid}:{target_gid}"
                    )

            os.chown(
                directory_path,
                target_uid,
                target_gid,
            )

    def _restore_blob(self, destination, blob):
        local_path = os.path.join(destination, blob.name)
        # Create a temp file that will be renamed to the target to ensure
        # atomicity, and ensure access mode is set from the beginning
        temp_path = local_path + secrets.token_hex()
        mode = int(blob.metadata["goog-reserved-posix-mode"], base=8)
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        target_uid = self.uid_mapping[blob.metadata["goog-reserved-posix-uid"]]
        target_gid = self.gid_mapping[blob.metadata["goog-reserved-posix-gid"]]
        os.fchown(fd, target_uid, target_gid)
        with os.fdopen(fd, mode="wb") as fh:
            blob.download_to_file(fh)
        os.rename(temp_path, local_path)
        os.utime(
            local_path,
            (
                int(blob.metadata["goog-reserved-file-atime"]),
                int(blob.metadata["goog-reserved-file-mtime"]),
            ),
        )

    def _restore_directory_times(self, manifest, destination):
        # Needs to be done after all the files have been written
        for directory, target_stat in manifest["directory_permissions"].items():
            directory_path = os.path.join(destination, directory)
            os.utime(directory_path, (target_stat["atime"], target_stat["mtime"]))

    def _get_remote_objects(self):
        try:
            blobs = self.bucket.list_blobs()
            for blob in blobs:
                if blob.name == MANIFEST_REMOTE_PATH:
                    continue
                blob.encryption_key = self.csek_key
                try:
                    blob.reload()
                except BadRequest as e:
                    if not e.errors:
                        raise e
                    if e.errors[0].get("reason") == "customerEncryptionKeyIsIncorrect":
                        self.logger.warning(
                            "Ignoring file %s with mismatched CSEK", blob.name
                        )
                        continue
                    if (
                        e.errors[0].get("reason")
                        == "resourceNotEncryptedWithCustomerEncryptionKey"
                    ):
                        self.logger.warning(
                            "Ignoring file %s which is not encrypted with a CSEK",
                            blob.name,
                        )
                        continue
                    raise e
                yield blob
        except Exception as e:
            self.logger.error(f"Failed to list bucket contents: {e}")
            sys.exit(1)

    def _scan_local_files(
        self, targets: List[str], exclude_pattern: Optional[str], remote_objects
    ):
        exclude_regex = re.compile(exclude_pattern) if exclude_pattern else None
        action_queue = []

        for target in targets:
            target_stat = os.stat(target)
            if stat.S_ISDIR(target_stat.st_mode):
                for root, dirs, filenames in os.walk(target):
                    dir_stat = os.stat(root)
                    self.manifest_data["directory_permissions"][root] = {
                        "mode": f"{stat.S_IMODE(dir_stat.st_mode):o}",
                        "uid": str(dir_stat.st_uid),
                        "gid": str(dir_stat.st_gid),
                        "mtime": dir_stat.st_mtime,
                        "atime": dir_stat.st_atime,
                    }
                    self.found_gids.add(dir_stat.st_gid)
                    self.found_uids.add(dir_stat.st_uid)

                    for filename in filenames:
                        local_path = os.path.join(root, filename)

                        # Apply exclude pattern
                        if exclude_regex and exclude_regex.search(local_path):
                            continue

                        path_stat = os.stat(local_path)
                        if stat.S_ISREG(path_stat.st_mode):
                            action = self._process_path(
                                local_path, path_stat, remote_objects
                            )
                            if action is not None:
                                action_queue.append(action)
                        else:
                            self.logger.debug(
                                f"Skipping object which is neither file nor directory: {local_path} (file type {stat.S_IFMT(path_stat.st_mode)})"
                            )

            elif stat.S_ISREG(target_stat.st_mode):
                action = self._process_path(target, target_stat, remote_objects)
                if action is not None:
                    action_queue.append(action)
            else:
                # TODO: handle symlinks?
                self.logger.info(
                    f"Skipping target which is neither file nor directory: {target} (file type {stat.S_IFMT(target_stat.st_mode)})"
                )
        return action_queue

    def _process_path(self, path, path_stat, remote_objects):
        self.found_gids.add(path_stat.st_gid)
        self.found_uids.add(path_stat.st_uid)

        # Convert to relative path for GCS
        remote_path = path.lstrip("/")
        local_metadata = {
            "goog-reserved-posix-mode": f"{stat.S_IMODE(path_stat.st_mode):o}",
            "goog-reserved-posix-gid": str(path_stat.st_gid),
            "goog-reserved-posix-uid": str(path_stat.st_uid),
            "goog-reserved-file-mtime": str(int(path_stat.st_mtime)),
            "goog-reserved-file-atime": str(int(path_stat.st_atime)),
        }
        local_hash = get_file_md5(path)

        blob = remote_objects.pop(remote_path, None)

        action = None
        if blob is None or local_hash != blob.md5_hash:
            action = "upload"
        elif local_metadata != blob.metadata:
            action = "metadata"

        if action is not None:
            return TargetFile(
                path,
                remote_path,
                local_hash,
                local_metadata,
                action,
            )

    def _upload_files(self, action_queue):
        if self.dry_run:
            for target_file in action_queue:
                object_path = target_file.local_path or target_file.remote_path
                self.logger.info(f"DRY RUN: {target_file.action}: {object_path}")
            return

        for target_file in action_queue:
            if target_file.action == "upload":
                blob = self.bucket.blob(
                    target_file.remote_path,
                    encryption_key=self.csek_key,
                )
                blob.metadata = target_file.metadata
                blob.upload_from_filename(target_file.local_path, checksum="md5")
                self.logger.info(f"Uploaded: {target_file.local_path}")
            elif target_file.action == "metadata":
                blob = self.bucket.blob(
                    target_file.remote_path,
                    encryption_key=self.csek_key,
                )
                blob.metadata = target_file.metadata
                blob.patch()
                self.logger.info(f"Updated metadata: {target_file.local_path}")
            elif target_file.action == "delete":
                blob = self.bucket.blob(target_file.remote_path)
                blob.delete()
                self.logger.info(f"Deleted: {target_file.remote_path}")

    def _upload_manifest(self):
        """Upload manifest file if changed"""
        local_manifest = self._generate_manifest()
        manifest_hash = base64.b64encode(
            hashlib.md5(local_manifest.encode("utf-8")).digest()
        ).decode("utf-8")
        manifest_blob = self.bucket.blob(
            MANIFEST_REMOTE_PATH, encryption_key=self.csek_key
        )
        if not manifest_blob.exists():
            if self.dry_run:
                self.logger.info("DRY RUN: Manifest not present, would upload")
                return

            manifest_blob.md5_hash = manifest_hash
            manifest_blob.upload_from_string(
                local_manifest, content_type="application/json"
            )
            self.logger.info("Uploaded first backup manifest")
            return

        try:
            manifest_blob.reload()
        except BadRequest as e:
            if (
                e.errors
                and e.errors[0].get("reason") == "customerEncryptionKeyIsIncorrect"
            ):
                self.logger.warning(
                    "Mismatched CSEK key on manifest, ignoring and re-uploading"
                )
            else:
                raise e

        if manifest_blob.md5_hash == manifest_hash:
            self.logger.info("Manifest unchanged, skipping upload")
            return

        if self.dry_run:
            self.logger.info("DRY RUN: Would update manifest file")
            return

        manifest_blob.md5_hash = manifest_hash
        manifest_blob.upload_from_string(
            local_manifest, content_type="application/json"
        )
        self.logger.info("Updated manifest file")

    def _generate_manifest(self) -> str:
        """Generate manifest with permissions and uid/gid mappings"""
        for uid in self.found_uids:
            username = pwd.getpwuid(uid).pw_name
            self.manifest_data["uid_mapping"][str(uid)] = username

        for gid in self.found_gids:
            groupname = grp.getgrgid(gid).gr_name
            self.manifest_data["gid_mapping"][str(gid)] = groupname

        manifest_json = json.dumps(self.manifest_data, indent=2, sort_keys=True)
        return manifest_json


def get_file_md5(filepath: str) -> str:
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(16 * 2**10), b""):
            hash_md5.update(chunk)
    return base64.b64encode(hash_md5.digest()).decode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="Path to configuration file")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without actually uploading",
    )
    parser.add_argument("-r", "--restore", help="Restore to this directory")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Include debug logs to stdout",
    )

    args = parser.parse_args()

    backup_manager = BackupManager(args.config, args.dry_run, args.verbose)
    if args.restore:
        backup_manager.run_restore(args.restore)
    else:
        backup_manager.run_backup()


if __name__ == "__main__":
    main()
