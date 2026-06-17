import os
import tempfile
import subprocess
import shutil
import urllib.parse

import salt.utils.path


DOTFILES_GIT_DIR = '.dotfiles'


def __virtual__():
    if salt.utils.path.which('git'):
        return True
    return False, 'Missing a git binary'


def repo(name, repo, user):
    ret = {
        'name': name,
        'comment': '',
        'result': True,
        'changes': {},
    }
    repo_url, branch = urllib.parse.urldefrag(repo)
    branch = branch or 'master'
    home_dir = os.path.expanduser('~%s' % user)
    git_dir = os.path.expanduser('~%s/%s' % (user, DOTFILES_GIT_DIR))
    try:
        if not os.path.exists(git_dir):
            _clone_new_repo(home_dir, git_dir, repo_url, branch)
            ret['comment'] = 'Cloned branch %s from repo %s\n' % (branch, repo_url)

        changes = _pull_repo(home_dir, git_dir, branch)
    except subprocess.CalledProcessError as error:
        ret['result'] = False
        stderr = error.stderr.decode('utf-8') if error.stderr else str(error)
        ret['comment'] += 'stderr: %s\n' % stderr
        return ret

    if changes:
        ret['comment'] += 'The following dotfiles were updated'
        ret['changes']['changes'] = changes

    return ret


def _git(git_dir, args, cwd):
    """Run a git command, capturing output to avoid leaking into salt's stdout."""
    subprocess.run(
        ['git', '--git-dir', git_dir] + args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _pull_repo(home_dir, git_dir, branch):
    # Ensure HEAD points to a local branch BEFORE fetching.
    # If a previous run left HEAD pointing to a remote tracking ref
    # (refs/remotes/origin/<branch>), git fetch fails with
    # "can't fetch into checked-out branch". This also fixes existing broken clones.
    _git(git_dir, ['update-ref', 'refs/heads/%s' % branch, 'origin/%s' % branch], home_dir)
    _git(git_dir, ['symbolic-ref', 'HEAD', 'refs/heads/%s' % branch], home_dir)
    _git(git_dir, ['fetch', '--all'], home_dir)
    # reset --hard will also advance refs/heads/<branch> to origin/<branch>
    # since HEAD is a symbolic ref pointing there.
    _git(git_dir, ['reset'], home_dir)
    changes = subprocess.run(
        ['git', '--git-dir', git_dir, 'diff', '-R', 'origin/%s' % branch],
        cwd=home_dir,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    _git(git_dir, ['reset', '--hard', 'origin/%s' % branch], home_dir)

    return changes


def _clone_new_repo(home_dir, git_dir, repo, branch):
    with tempfile.TemporaryDirectory(dir=home_dir) as tempdir:
        subprocess.run(
            ['git', 'clone', repo, tempdir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.rename(os.path.join(tempdir, '.git'), git_dir)
        _git(git_dir, ['config', 'status.showUntrackedFiles', 'no'], home_dir)
