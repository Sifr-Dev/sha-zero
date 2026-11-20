# Verification evidence

This log records commands and results for `renaissance/sha256-verification` on 2026-11-20 (Africa/Cairo), on x86-64 Linux. No output is copied from the baseline README.

## Baseline inspection

- `origin/HEAD` and the default branch resolve to `origin/master` at `9876dd4af51d2bc11fa10348b10791def108d1ce`.
- Remote branches inspected: `origin/master`, `origin/portfolio/account-rename-sifr-salahy`, and `origin/portfolio/account-sifr-dev`.
- Baseline had no CI, no build system, and no separate test harness. Its in-source self-test covered four ASCII vectors only.
- Baseline defects confirmed by inspection: `fread()` errors were treated as EOF, arguments after the input path were ignored, `--selftest` accepted trailing arguments, and a compiled executable was tracked.

## Test coverage

- FIPS 180-4 one-shot and streaming vectors: empty, `abc`, the 448-bit and 896-bit multi-block messages, and one million `a` bytes.
- Every split of the FIPS messages; byte-at-a-time hashes for sizes 0–257; every split of a 1025-byte deterministic binary message; explicit embedded-NUL, `0x80`, and `0xff` bytes.
- Const/repeatable `finish()`, continued updates after `finish()`, copies, and empty-null versus invalid nonempty-null API calls.
- Deterministic random `hashlib` differential tests over lengths 0–257, block/read-buffer boundaries, 100 randomized lengths, one million bytes, and 8 MiB + 137 bytes. Every case checks both stdin and a real file.
- CLI implicit/explicit stdin, binary files and filenames with spaces, large I/O, invalid commands/arity/options, nonexistent inputs, directory and `/proc/self/mem` read failures, a write-only stdin descriptor, and `/dev/full` output failure.
- GCC and Clang release builds with strict warnings as errors; GCC debug ASan+UBSan; install/package version fixed at 0.1.0.

## Local results

Toolchain: GCC 16.2.1, Clang 23.1.5, CMake 4.5.0, and Python 3.14.10.

Each configuration below was built with `-DSIFR_WARNINGS_AS_ERRORS=ON`, then run with `ctest --output-on-failure`:

| Configuration | Result | CTest time |
| --- | --- | --- |
| GCC 16.2.1, Release | **3/3 passed** | 1.98 s |
| Clang 23.1.5, Release | **3/3 passed** | 1.94 s |
| GCC 16.2.1, Debug, ASan+UBSan, leak detection, UBSan halt-on-error | **3/3 passed** | 14.28 s |

The three CTest entries are `unit`, `differential`, and `cli`. The differential entry reports **372 inputs**, each checked through both stdin and a real file. The unit entry reports `PASS: FIPS vectors, million-a, all boundary splits, binary data, API contracts`. No sanitizer diagnostics occurred.

Release packaging was also exercised:

```console
$ ./build-gcc-release/sifr-crypt --version
sifr-crypt 0.1.0
$ cmake --install build-gcc-release --prefix "$PWD/build-gcc-release/stage"
-- Install configuration: "Release"
$ tar -czf build-gcc-release/sifr-crypt-0.1.0-linux-x86_64.tar.gz -C build-gcc-release/stage .
```

The archive contained the CLI, static library, public header, and exported CMake target. The old tracked 22,120-byte executable is intentionally deleted; build products are ignored. The old monolithic source is replaced by the public header, library source, and CLI entry point.

During development, strict warnings caught test-local shadowing/unused-code issues and the FIPS tests caught a newly introduced `K[47]` transcription typo. Both were corrected. Two incorrect hand-copied expected digests were independently checked against `hashlib` and fixed; no failing assertions or sanitizer findings remain.

## GitHub Actions results

PR [#1](https://github.com/Sifr-Dev/sha-zero/pull/1) triggered both events successfully:

- Push run [44795717959](https://github.com/Sifr-Dev/sha-zero/actions/runs/44795717959): **success** in 39 s.
- Pull-request run [44795730577](https://github.com/Sifr-Dev/sha-zero/actions/runs/44795730577): **success** in 42 s.
- In each run, `gcc-release`, `gcc-debug-sanitized`, `clang-release`, and `package` all completed successfully.
