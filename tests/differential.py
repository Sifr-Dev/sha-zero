#!/usr/bin/env python3
"""Differentially check deterministic binary inputs against Python hashlib."""

import hashlib
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def check(cli: Path, data: bytes, description: str, work: Path) -> None:
    expected = hashlib.sha256(data).hexdigest()
    stdin_result = subprocess.run(
        [cli, "sha256", "-"], input=data, capture_output=True, check=False
    )
    assert stdin_result.returncode == 0, (description, stdin_result.stderr)
    assert stdin_result.stderr == b"", (description, stdin_result.stderr)
    assert stdin_result.stdout == f"{expected}\n".encode(), description

    path = work / "input.bin"
    path.write_bytes(data)
    file_result = subprocess.run(
        [cli, "sha256", path], capture_output=True, check=False
    )
    assert file_result.returncode == 0, (description, file_result.stderr)
    assert file_result.stdout == stdin_result.stdout, description


def main() -> None:
    cli = Path(sys.argv[1]).resolve()
    rng = random.Random(0x53484941)
    lengths = list(range(0, 258))
    lengths += [511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097,
                65535, 65536, 65537, 1_000_000]
    lengths += [rng.randrange(0, 200_000) for _ in range(100)]

    with tempfile.TemporaryDirectory(prefix="sifr-differential-") as temp:
        work = Path(temp)
        for index, length in enumerate(lengths):
            data = rng.randbytes(length)
            check(cli, data, f"random case {index}, {length} bytes", work)

        # Incompressible data with a size not divisible by the CLI read buffer.
        data = rng.randbytes(8 * 1024 * 1024 + 137)
        check(cli, data, f"large I/O, {len(data)} bytes", work)

    print(f"PASS: {len(lengths) + 1} deterministic hashlib differential cases")


if __name__ == "__main__":
    main()
