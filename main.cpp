#include "sifr/sha256.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>

namespace {

int usage()
{
    std::cerr << "usage: sifr-crypt sha256 [file|-]\n";
    return 2;
}

int hash_stream(std::FILE* stream, const char* name)
{
    sifr::Sha256 hash;
    unsigned char buffer[64 * 1024];

    for (;;) {
        const std::size_t count = std::fread(buffer, 1, sizeof(buffer), stream);
        if (count != 0) {
            hash.update(buffer, count);
        }
        if (count < sizeof(buffer)) {
            if (std::ferror(stream)) {
                const int error = errno;
                std::cerr << "sifr-crypt: cannot read " << name << ": "
                          << std::strerror(error) << '\n';
                return 1;
            }
            if (std::feof(stream)) {
                break;
            }
            std::cerr << "sifr-crypt: short read from " << name << '\n';
            return 1;
        }
    }

    std::cout << hash.hexdigest() << '\n';
    std::cout.flush();
    if (!std::cout) {
        std::cerr << "sifr-crypt: cannot write digest\n";
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "sifr-crypt 0.1.0\n";
        return 0;
    }
    if (argc < 2 || argc > 3 || std::string(argv[1]) != "sha256") {
        return usage();
    }

    try {
        if (argc == 2 || std::string(argv[2]) == "-") {
            return hash_stream(stdin, "stdin");
        }

        std::FILE* file = std::fopen(argv[2], "rb");
        if (file == nullptr) {
            const int error = errno;
            std::cerr << "sifr-crypt: cannot open " << argv[2] << ": "
                      << std::strerror(error) << '\n';
            return 1;
        }
        const int result = hash_stream(file, argv[2]);
        if (std::fclose(file) != 0 && result == 0) {
            const int error = errno;
            std::cerr << "sifr-crypt: cannot close " << argv[2] << ": "
                      << std::strerror(error) << '\n';
            return 1;
        }
        return result;
    } catch (const std::exception& error) {
        std::cerr << "sifr-crypt: " << error.what() << '\n';
        return 1;
    }
}
