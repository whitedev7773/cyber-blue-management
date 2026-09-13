"""Explicit user-run helper. Requires installed and authenticated GitHub CLI."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

def run(*args, check=True):
    return subprocess.run(args, cwd=ROOT, check=check, text=True, capture_output=True)

def main():
    parser = argparse.ArgumentParser(description='Create a new GitHub repository and push this MVP.')
    parser.add_argument('--name', default='aegis-review')
    parser.add_argument('--public', action='store_true', help='Explicitly publish publicly; default private.')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}', args.name):
        parser.error('Use a repository name, not a URL or owner/name.')
    for binary in ('git', 'gh'):
        if not shutil.which(binary):
            sys.exit(f'{binary} is required. Install it first.')
    if run('gh', 'auth', 'status', check=False).returncode:
        sys.exit('Authenticate first: gh auth login')
    if not (ROOT / '.git').exists():
        run('git', 'init', '-b', 'main')
    if run('git', 'remote', 'get-url', 'origin', check=False).returncode == 0:
        sys.exit('An origin already exists. Stopped without changing it.')
    for key in ('user.name', 'user.email'):
        if run('git', 'config', key, check=False).returncode:
            sys.exit(f'Set your commit identity first: git config {key} VALUE')
    # Explicit allowlist avoids committing uploaded data or unrelated workspace files.
    run('git', 'add', 'README.md', 'SECURITY.md', 'pyproject.toml', '.gitignore', '.github', 'aegis', 'web', 'examples', 'tests', 'docs', 'scripts')
    if run('git', 'diff', '--cached', '--quiet', check=False).returncode:
        run('git', 'commit', '-m', 'feat: add local defensive review MVP')
    visibility = '--public' if args.public else '--private'
    completed = run('gh', 'repo', 'create', args.name, visibility, '--source', '.', '--remote', 'origin', '--push', '--description', 'Local defensive configuration review and evidence dashboard')
    print(completed.stdout.strip() or 'Repository created and pushed.')

if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.strip() or f'Command failed with exit code {exc.returncode}', file=sys.stderr)
        sys.exit(exc.returncode)
