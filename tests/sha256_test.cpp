#include "sifr/sha256.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using sifr::Sha256;

int failures = 0;

void expect(bool condition, const std::string& description)
{
    if (!condition) {
        std::cerr << "FAIL: " << description << '\n';
        ++failures;
    }
}

std::string digest_bytes(const std::vector<std::uint8_t>& input)
{
    return Sha256::hexdigest(input.data(), input.size());
}

void test_nist_vectors()
{
    struct Vector {
        const char* input;
        const char* digest;
    };
    const Vector vectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    };

    for (const auto& vector : vectors) {
        const std::string input(vector.input);
        expect(Sha256::hexdigest(input.data(), input.size()) == vector.digest,
               std::string("FIPS one-shot: ") + vector.input);

        for (std::size_t split = 0; split <= input.size(); ++split) {
            Sha256 streaming;
            streaming.update(input.data(), split);
            streaming.update(input.data() + split, input.size() - split);
            expect(streaming.hexdigest() == vector.digest,
                   "FIPS streaming split " + std::to_string(split));
        }
    }

    const std::vector<std::uint8_t> million_a(1'000'000, static_cast<std::uint8_t>('a'));
    const std::string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    expect(digest_bytes(million_a) == expected, "FIPS million-a one-shot");
    for (std::size_t chunk : {std::size_t{1}, std::size_t{55}, std::size_t{56},
                              std::size_t{63}, std::size_t{64}, std::size_t{65},
                              std::size_t{4096}, std::size_t{65536}}) {
        Sha256 streaming;
        for (std::size_t offset = 0; offset < million_a.size(); offset += chunk) {
            const std::size_t count = std::min(chunk, million_a.size() - offset);
            streaming.update(million_a.data() + offset, count);
        }
        expect(streaming.hexdigest() == expected,
               "FIPS million-a chunk " + std::to_string(chunk));
    }
}

void test_binary_and_boundaries()
{
    const std::array<std::uint8_t, 8> binary = {0x00, 0xff, 0x80, 0x7f, 0x00, 0x01, 0xfe, 0x00};
    const std::string binary_expected = "93a70af84d6ee6366c1eaa6540ca59ffde52de8a185b7ab70f7afd3d36ec21df";
    expect(Sha256::hexdigest(binary.data(), binary.size()) == binary_expected, "embedded NUL and binary bytes");

    std::vector<std::uint8_t> data(4097);
    std::uint32_t state = 0x12345678U;
    for (auto& value : data) {
        state = state * 1664525U + 1013904223U;
        value = static_cast<std::uint8_t>(state >> 24U);
    }
    for (std::size_t size = 0; size <= 257; ++size) {
        const std::string boundary_expected = Sha256::hexdigest(data.data(), size);
        Sha256 byte_at_a_time;
        for (std::size_t i = 0; i < size; ++i) {
            byte_at_a_time.update(data.data() + i, 1);
        }
        expect(byte_at_a_time.hexdigest() == boundary_expected,
               "every byte split at size " + std::to_string(size));

        Sha256 split_hash;
        split_hash.update(data.data(), size / 2);
        split_hash.update(data.data() + size / 2, size - size / 2);
        expect(split_hash.hexdigest() == boundary_expected, "two-part boundary hash");
    }

    // Every two-chunk split of an input spanning multiple blocks.
    const std::size_t size = 1025;
    const std::string multiblock_expected = Sha256::hexdigest(data.data(), size);
    for (std::size_t split = 0; split <= size; ++split) {
        Sha256 streaming;
        streaming.update(data.data(), split);
        streaming.update(data.data() + split, size - split);
        expect(streaming.hexdigest() == multiblock_expected, "multi-block split " + std::to_string(split));
    }
}

void test_api_contract()
{
    const std::string input = "abc";
    expect(Sha256::hexdigest(nullptr, 0)
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "null pointer with empty input");

    bool null_threw = false;
    try {
        static_cast<void>(Sha256::hash(nullptr, 1));
    } catch (const std::invalid_argument&) {
        null_threw = true;
    }
    expect(null_threw, "null pointer with nonempty input throws invalid_argument");

    Sha256 hash;
    hash.update(nullptr, 0);
    hash.update(input.data(), input.size());
    const std::string first = hash.hexdigest();
    expect(first == hash.hexdigest(), "finish is repeatable");
    expect(first == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "const finish result");
    hash.update(input.data(), input.size());
    expect(hash.hexdigest() == Sha256::hexdigest("abcabc", 6), "finish does not consume state");

    Sha256 copied = hash;
    expect(copied.hexdigest() == hash.hexdigest(), "hash state can be copied");
}

} // namespace

int main()
{
    test_nist_vectors();
    test_binary_and_boundaries();
    test_api_contract();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "PASS: FIPS vectors, million-a, all boundary splits, binary data, API contracts\n";
    return 0;
}
