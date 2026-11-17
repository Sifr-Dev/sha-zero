<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="sifr-crypt — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# sifr-crypt

zero-dependency SHA-256 (FIPS 180-4) hasher, written from the spec — no
OpenSSL, no libsodium, no crates, no pip. C++17, posix only.

```sh
sifr-crypt sha256 file.bin        # hash a file
sifr-crypt sha256 -               # hash stdin
sifr-crypt sha256 --selftest      # FIPS 180-4 / RFC 4231-style vectors
```

## evidence (this machine, 2026-11-17)

```console
$ ./sifr-crypt sha256 --selftest
SHA256_SELFTEST PASS got=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA256_SELFTEST PASS got=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
SHA256_SELFTEST PASS got=248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
SHA256_SELFTEST PASS got=d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
$ ./sifr-crypt sha256 /tmp/rand.bin   # matches `sha256sum` byte-exact
524689c2769d2ac768af7ed6f2160a3b514561217b033f139cfd06f81388d23a
```

## build

```sh
g++ -O2 -std=c++17 -o sifr-crypt sha256.cpp
```

## scope

SHA-256 only, streaming, files or stdin. No HMAC yet, no SHA-224/512, no
password hashing (use Argon2 for that).

## license

`MIT` — see `LICENSE`. built from zero.
