"""Repair the non-UTF-8 byte nodriver ships with in 0.48+.

nodriver's generated CDP module contains a raw 0xb1 (±) inside a comment with no
encoding declaration, so importing it raises SyntaxError on any Python that
insists on UTF-8 source. Confirmed on 0.48.1, 0.50.1 and 0.50.5.

Idempotent: run it after every `uv sync`, which reverts the file.
"""

from __future__ import annotations

import sys

BAD = b"\xb1Inf"
GOOD = b"plus-minus Inf"


def patch() -> tuple[int, str]:
    try:
        import nodriver
    except ImportError:
        return 0, "nodriver is not installed"

    from pathlib import Path

    root = Path(nodriver.__file__).parent / "cdp"
    if not root.is_dir():
        return 0, f"no cdp directory under {root}"

    touched = 0
    for file in root.glob("*.py"):
        raw = file.read_bytes()
        if BAD not in raw:
            continue
        file.write_bytes(raw.replace(BAD, GOOD))
        touched += 1
    return touched, str(root)


def main() -> int:
    touched, where = patch()
    if touched:
        print(f"patched {touched} nodriver cdp file(s) under {where}")
        return 0
    print(f"nothing to patch: {where}")
    # A clean tree is a success; an unimportable nodriver is caught by the caller.
    return 0


if __name__ == "__main__":
    sys.exit(main())
