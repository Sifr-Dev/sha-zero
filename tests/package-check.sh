#!/bin/sh
set -eu
stage=${TMPDIR:-/tmp}/sifr-crypt-package-$$
consumer=${TMPDIR:-/tmp}/sifr-crypt-consumer-$$
trap 'rm -rf "$stage" "$consumer"' EXIT HUP INT TERM
cmake -S . -B build-package -DCMAKE_BUILD_TYPE=Release
cmake --build build-package --parallel 2
cmake --install build-package --prefix "$stage/usr"
mkdir -p "$consumer"
cat > "$consumer/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(consumer LANGUAGES CXX)
find_package(sifr-crypt CONFIG REQUIRED)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE sifr::sha256)
EOF
cat > "$consumer/main.cpp" <<'EOF'
#include <sifr/sha256.h>
#include <string>
int main() {
  return sifr::Sha256::hexdigest("abc", 3) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ? 0 : 1;
}
EOF
cmake -S "$consumer" -B "$consumer/build" -DCMAKE_PREFIX_PATH="$stage/usr"
cmake --build "$consumer/build" --parallel 2
"$consumer/build/consumer"
"$stage/usr/bin/sifr-crypt" --version
