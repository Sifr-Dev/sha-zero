#ifndef SIFR_SHA256_H
#define SIFR_SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sifr {

class Sha256 {
public:
    static constexpr std::size_t digest_size = 32;
    using Digest = std::array<std::uint8_t, digest_size>;

    Sha256() noexcept;

    void update(const void* data, std::size_t size);
    Digest finish() const noexcept;
    std::string hexdigest() const;

    static Digest hash(const void* data, std::size_t size);
    static std::string hexdigest(const void* data, std::size_t size);

private:
    void process_block(const std::uint8_t* block) noexcept;

    std::array<std::uint32_t, 8> state_;
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t total_size_ = 0;
    std::size_t buffer_size_ = 0;
};

} // namespace sifr

#endif
