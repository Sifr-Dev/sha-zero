#include "sifr/sha256.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace sifr {
namespace {

constexpr std::array<std::uint32_t, 64> round_constants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned int count) noexcept
{
    return (value >> count) | (value << (32U - count));
}

} // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
{
}

void Sha256::update(const void* data, std::size_t size)
{
    if (size == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument("Sha256::update: null data with nonzero size");
    }
    constexpr std::uint64_t max_input_size = UINT64_MAX / 8U;
    if (size > max_input_size - total_size_) {
        throw std::length_error("Sha256: input exceeds the FIPS 180-4 length limit");
    }

    total_size_ += static_cast<std::uint64_t>(size);
    const auto* input = static_cast<const std::uint8_t*>(data);

    if (buffer_size_ != 0) {
        const std::size_t count = std::min(size, buffer_.size() - buffer_size_);
        std::memcpy(buffer_.data() + buffer_size_, input, count);
        buffer_size_ += count;
        input += count;
        size -= count;
        if (buffer_size_ == buffer_.size()) {
            process_block(buffer_.data());
            buffer_size_ = 0;
        }
    }

    while (size >= buffer_.size()) {
        process_block(input);
        input += buffer_.size();
        size -= buffer_.size();
    }

    if (size != 0) {
        std::memcpy(buffer_.data(), input, size);
        buffer_size_ = size;
    }
}

Sha256::Digest Sha256::finish() const noexcept
{
    // Hash the padded final blocks on a copy: finish() is const, repeatable,
    // and does not prevent further updates to the original hash.
    Sha256 final_state = *this;
    const std::uint64_t bit_size = final_state.total_size_ * 8U;

    final_state.buffer_[final_state.buffer_size_++] = 0x80;
    if (final_state.buffer_size_ > 56) {
        std::fill(final_state.buffer_.begin() + static_cast<std::ptrdiff_t>(final_state.buffer_size_),
                  final_state.buffer_.end(), 0);
        final_state.process_block(final_state.buffer_.data());
        final_state.buffer_size_ = 0;
    }
    std::fill(final_state.buffer_.begin() + static_cast<std::ptrdiff_t>(final_state.buffer_size_),
              final_state.buffer_.begin() + 56, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        final_state.buffer_[56 + i] = static_cast<std::uint8_t>(bit_size >> (56U - 8U * i));
    }
    final_state.process_block(final_state.buffer_.data());

    Digest digest{};
    for (std::size_t i = 0; i < final_state.state_.size(); ++i) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            digest[i * 4 + byte] = static_cast<std::uint8_t>(
                final_state.state_[i] >> (24U - 8U * byte));
        }
    }
    return digest;
}

Sha256::Digest Sha256::hash(const void* data, std::size_t size)
{
    Sha256 hash;
    hash.update(data, size);
    return hash.finish();
}

std::string Sha256::hexdigest() const
{
    static constexpr char digits[] = "0123456789abcdef";
    const Digest digest = finish();
    std::string result(digest.size() * 2, '0');
    for (std::size_t i = 0; i < digest.size(); ++i) {
        result[i * 2] = digits[digest[i] >> 4U];
        result[i * 2 + 1] = digits[digest[i] & 0x0fU];
    }
    return result;
}

std::string Sha256::hexdigest(const void* data, std::size_t size)
{
    Sha256 hash;
    hash.update(data, size);
    return hash.hexdigest();
}

void Sha256::process_block(const std::uint8_t* block) noexcept
{
    std::array<std::uint32_t, 64> words{};
    for (std::size_t i = 0; i < 16; ++i) {
        words[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24U)
            | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16U)
            | (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8U)
            | static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < words.size(); ++i) {
        const std::uint32_t s0 = rotate_right(words[i - 15], 7)
            ^ rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3U);
        const std::uint32_t s1 = rotate_right(words[i - 2], 17)
            ^ rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10U);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < words.size(); ++i) {
        const std::uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        const std::uint32_t choose = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + sum1 + choose + round_constants[i] + words[i];
        const std::uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

} // namespace sifr
