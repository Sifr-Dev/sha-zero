#!/usr/bin/env python3
"""Black-box CLI tests for input selection, binary data, and failure paths."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(cli: Path, *args: object, data: bytes = b"", **kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        [cli, *map(str, args)], input=data, capture_output=True, check=False, **kwargs
    )


def expect_failure(result: subprocess.CompletedProcess, text: str) -> None:
    assert result.returncode != 0, result
    assert result.stdout == b"", result.stdout
    assert text.encode() in result.stderr, result.stderr


def main() -> None:
    cli = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="sifr-cli-") as temp:
        root = Path(temp)
        samples = [b"", b"abc", bytes(range(256)) * 3, b"line one\nline two\x00\xff"]
        for index, data in enumerate(samples):
            expected = f"{hashlib.sha256(data).hexdigest()}\n".encode()
            implicit = run(cli, "sha256", data=data)
            assert implicit.returncode == 0 and implicit.stdout == expected
            assert implicit.stderr == b""
            explicit = run(cli, "sha256", "-", data=data)
            assert explicit.returncode == 0 and explicit.stdout == expected

            path = root / f"sample {index}.bin"
            path.write_bytes(data)
            from_file = run(cli, "sha256", path)
            assert from_file.returncode == 0 and from_file.stdout == expected
            assert from_file.stderr == b""

        large = bytes(range(256)) * 4097 + b"tail"
        large_path = root / "large.bin"
        large_path.write_bytes(large)
        expected = f"{hashlib.sha256(large).hexdigest()}\n".encode()
        assert run(cli, "sha256", large_path).stdout == expected
        assert run(cli, "sha256", data=large).stdout == expected

        expect_failure(run(cli), "usage:")
        expect_failure(run(cli, "sha512"), "usage:")
        expect_failure(run(cli, "sha256", "--selftest"), "cannot open")
        expect_failure(run(cli, "sha256", "a", "b"), "usage:")
        expect_failure(run(cli, "sha256", "--version"), "cannot open")
        expect_failure(run(cli, "sha256", root / "absent"), "cannot open")
        expect_failure(run(cli, "sha256", root), "cannot read")
        expect_failure(run(cli, "--version", "extra"), "usage:")
        version = run(cli, "--version")
        assert version.returncode == 0 and version.stdout == b"sifr-crypt 0.1.0\n"

        # A directory stream produces a read error on Linux, not an empty hash.
        if sys.platform.startswith("linux"):
            directory = run(cli, "sha256", root)
            assert directory.returncode == 1
            assert b"cannot read" in directory.stderr

            # /proc/self/mem yields an actual EIO on the first fread().
            proc_mem = Path("/proc/self/mem")
            if proc_mem.exists():
                unreadable = run(cli, "sha256", proc_mem)
                expect_failure(unreadable, "cannot read")

            # Reading from a write-only descriptor must report EBADF.
            read_fd, write_fd = os.pipe()
            try:
                with os.fdopen(read_fd, "rb", closefd=True) as read_end:
                    os.close(write_fd)
                    write_fd = -1
                    # The empty pipe gives EOF, so separately test a directory above.
                    empty_pipe = subprocess.run(
                        [cli, "sha256"], stdin=read_end, capture_output=True, check=False
                    )
                    assert empty_pipe.returncode == 0
            finally:
                if write_fd >= 0:
                    os.close(write_fd)

            # Dup2 a write-only descriptor onto stdin in the child.
            write_only = os.open(root / "write-only", os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                def replace_stdin() -> None:
                    os.dup2(write_only, 0)
                bad_stdin = subprocess.run(
                    [cli, "sha256"], capture_output=True, check=False,
                    preexec_fn=replace_stdin,
                )
                expect_failure(bad_stdin, "cannot read")
            finally:
                os.close(write_only)

            # /dev/full forces a stdout failure only after all input is hashed.
            with open("/dev/full", "wb") as full:
                output_error = subprocess.run(
                    [cli, "sha256"], input=b"abc", stdout=full,
                    stderr=subprocess.PIPE, check=False,
                )
            assert output_error.returncode != 0
            assert b"cannot write digest" in output_error.stderr

    print("PASS: CLI stdin/files/binary/large I/O/invalid arguments/read/write failures")


if __name__ == "__main__":
    main()
