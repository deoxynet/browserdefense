#!/usr/bin/env python3
"""Reject credential files and private key/token literals in tracked source."""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PATTERNS = {
    'private PEM key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\n\r\s]+[A-Za-z0-9+/=]{40,}'),
    'Stripe secret token': re.compile(rb'sk_(?:test|live)_[A-Za-z0-9]{12,}'),
    'GitHub token': re.compile(rb'(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{30,}'),
    'AWS access key': re.compile(rb'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    'private JWK parameter': re.compile(rb'["\']d["\']\s*:\s*["\'][A-Za-z0-9_-]{32,}["\']'),
}


def main():
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    failures = []
    for name in filter(None, paths):
        path = ROOT / name
        if not path.is_file():
            continue
        if (path.name.startswith('.env') and path.name != '.env.example'
                or path.suffix in {'.pem', '.key', '.p12', '.pfx', '.jwk'}
                or name.startswith(('.wrangler/', 'keys/'))):
            failures.append((name, 'credential or local state file'))
        data = path.read_bytes()
        for label, pattern in PATTERNS.items():
            if pattern.search(data):
                failures.append((name, label))
    for name, label in failures:
        # Never print matched credentials to CI logs.
        print(f'{name}: {label}', file=sys.stderr)
    if failures:
        return 1
    print('Tracked source credential checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
