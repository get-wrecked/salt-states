# gcloud-backup

Backup to GCS. Target bucket should be configured with both versioning and retention for as long as you'd like to retain old versions, and a lifecycle rule if you want to clean up old versions of files.
The script in this module provides preservation of posix attributes similarly to gcloud/gsutil, but unlike gcloud it has CSEK support that doesn't expose the key on the command line, it can preserve posix attributes of directories and not just files, it will do a pure metadata update if any of the posix attributes change without the file contents changing, and it'll restore uids/gids based on the string names, not just the numeric ids (which might be different between systems).


## Requirements

- Python 3.6+ with `google-cloud-storage` package: `pip install google-cloud-storage`
- Google Cloud credentials configured via ADC, or path to a credentials file specified in
  the config as `credentials_path`.


## Configuration

Create a JSON config file:

```json
{
  "bucket_name": "my-backup-bucket",
  "targets": [
    "/etc",
    "/home/user/data",
    "/root/.ssh/authorized_keys"
  ],
  "exclude": "\\.(sock|tmp)$",
  "csek_key": "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG9Xb3JsZA=="
}
```

- `bucket_name` (required): GCS bucket name
- `targets` (required): List of files and directories to backup
- `exclude`: Regex pattern for files to exclude
- `csek_key`: Base64-encoded CSEK encryption key

## Usage

### Backup
```
python3 backup.py config.json [--dry-run]
```

### Restore
```
python3 backup.py config.json --restore /path/to/restore/ [--dry-run]
```
