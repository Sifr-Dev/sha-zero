// sifr-crypt — zero-dependency SHA-256 (FIPS 180-4) hasher.
//   sifr-crypt sha256 [file|-]     (stdin default)
//   sifr-crypt sha256 --selftest
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

struct Sha256 {
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    uint64_t total_len = 0;
    uint8_t buf[64];
    size_t buf_len = 0;

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void block(const uint8_t* p) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) | (uint32_t(p[i * 4 + 2]) << 8) | p[i * 4 + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        while (len > 0) {
            size_t take = 64 - buf_len;
            if (take > len) take = len;
            memcpy(buf + buf_len, data, take);
            buf_len += take;
            data += take;
            len -= take;
            if (buf_len == 64) {
                block(buf);
                buf_len = 0;
            }
        }
    }

    void final(uint8_t out[32]) {
        uint64_t bit_len = total_len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buf_len != 56) update(&zero, 1);
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; i++) lenbuf[i] = uint8_t(bit_len >> (56 - i * 8));
        // bypass: write length without going through update() accounting
        for (int i = 0; i < 8; i++) buf[buf_len++] = lenbuf[i];
        block(buf);
        for (int i = 0; i < 8; i++) {
            out[i * 4] = uint8_t(h[i] >> 24);
            out[i * 4 + 1] = uint8_t(h[i] >> 16);
            out[i * 4 + 2] = uint8_t(h[i] >> 8);
            out[i * 4 + 3] = uint8_t(h[i]);
        }
    }
};

static std::string hex(const uint8_t* d, size_t n) {
    char buf[3];
    std::string s;
    for (size_t i = 0; i < n; i++) { snprintf(buf, sizeof buf, "%02x", d[i]); s += buf; }
    return s;
}

static bool selftest() {
    struct Vec { const char* msg; const char* want; };
    const Vec vecs[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
    };
    for (const auto& v : vecs) {
        Sha256 s;
        s.update(reinterpret_cast<const uint8_t*>(v.msg), strlen(v.msg));
        uint8_t out[32];
        s.final(out);
        std::string got = hex(out, 32);
        bool ok = got == v.want;
        printf("SHA256_SELFTEST %s got=%s\n", ok ? "PASS" : "FAIL", got.c_str());
        if (!ok) return false;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "sha256") {
        if (argc >= 3 && std::string(argv[2]) == "--selftest") {
            return selftest() ? 0 : 1;
        }
        Sha256 s;
        uint8_t buf[65536];
        FILE* f = stdin;
        if (argc >= 3 && std::string(argv[2]) != "-") {
            f = fopen(argv[2], "rb");
            if (!f) { fprintf(stderr, "sifr-crypt: cannot open %s\n", argv[2]); return 2; }
        }
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) s.update(buf, n);
        if (f != stdin) fclose(f);
        uint8_t out[32];
        s.final(out);
        printf("%s\n", hex(out, 32).c_str());
        return 0;
    }
    fprintf(stderr, "usage: sifr-crypt sha256 [file|-] [--selftest]\n");
    return 2;
}
