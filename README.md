<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="sifr-crypt — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# sifr-crypt

Zero-dependency SHA-256 (FIPS 180-4), written from the specification in C++17.
The reusable `sifr::Sha256` library and `sifr-crypt` CLI support arbitrary binary
input without OpenSSL or other crypto dependencies.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Strict warnings are errors by default. A GCC/Clang sanitizer build is available:

```sh
cmake -S . -B build-sanitized -DCMAKE_BUILD_TYPE=Debug -DSIFR_ENABLE_SANITIZERS=ON
cmake --build build-sanitized
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-sanitized --output-on-failure
```

## CLI

```sh
./build/sifr-crypt sha256 file.bin  # hash a file
./build/sifr-crypt sha256 -         # hash stdin
./build/sifr-crypt sha256           # stdin is the default
./build/sifr-crypt --version        # 0.1.0
```

The CLI prints only the lowercase digest on success. Open, read, close, and
output failures produce a diagnostic and nonzero status. Exactly one optional
file argument is accepted; `-` explicitly selects stdin.

## Library API

```cpp
#include <sifr/sha256.h>

sifr::Sha256 hash;
hash.update(first.data(), first.size());
hash.update(second.data(), second.size());
std::string hex = hash.hexdigest();

// One-shot; data may be null only when size is zero.
std::string empty = sifr::Sha256::hexdigest(nullptr, 0);
```

`update()` accepts unaligned binary buffers and rejects a null pointer with a
nonzero size. `finish()`/`hexdigest()` are const and repeatable; they do not
consume the state, so updates may continue. `finish()` returns a 32-byte
`Sha256::Digest`. Inputs must satisfy the FIPS 180-4 length limit (less than
2^64 bits). Copying a hash copies its complete streaming state.

## Verification

Tests include FIPS one-shot and streaming vectors (including one million `a`),
all padding/buffer split boundaries, binary data, deterministic random
`hashlib` differentials, large files/stdin, invalid arguments, and real I/O
failures. See [docs/verification.md](docs/verification.md) for recorded local
and CI evidence.

## Scope

SHA-256 only. This is not HMAC, password hashing, or a general crypto library;
use Argon2 for password hashing. No SHA-224 or SHA-512.

## License

`MIT` — see `LICENSE`. Built from zero.
