#!/usr/bin/env python3

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET_FILES = sorted((ROOT / 'packet').glob('*.[ch]'))

ALLOWED_CAP_CALLS = {
    'cap_clear',
    'cap_free',
    'cap_get_proc',
    'cap_set_proc',
    'cap_t',
}

C_TOKEN = re.compile(r'\b(?:cap_[a-zA-Z0-9_]+|CAP_[A-Z0-9_]+)\b')


def strip_c_comments_and_strings(source):
    return re.sub(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: '\n' * match.group(0).count('\n'),
        source,
        flags=re.DOTALL,
    )


def main():
    errors = []

    for path in PACKET_FILES:
        source = strip_c_comments_and_strings(path.read_text())

        for match in C_TOKEN.finditer(source):
            token = match.group(0)

            if token.startswith('CAP_'):
                errors.append((path, token))
                continue

            if token not in ALLOWED_CAP_CALLS:
                errors.append((path, token))

    if errors:
        for path, token in errors:
            print(f'{path.relative_to(ROOT)}: disallowed capability token {token}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
