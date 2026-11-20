cmake_minimum_required(VERSION 3.16)
project(sifr-crypt VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(Python3 COMPONENTS Interpreter)

option(SIFR_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(SIFR_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(SIFR_ENABLE_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "SIFR_ENABLE_SANITIZERS requires GCC or Clang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

add_library(sifr_sha256 src/sha256.cpp)
set_target_properties(sifr_sha256 PROPERTIES EXPORT_NAME sha256)
add_library(sifr::sha256 ALIAS sifr_sha256)
target_include_directories(sifr_sha256 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(sifr_sha256 PUBLIC cxx_std_17)

add_executable(sifr-crypt main.cpp)
target_link_libraries(sifr-crypt PRIVATE sifr::sha256)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    foreach(target sifr_sha256 sifr-crypt)
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
        if(SIFR_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endforeach()
elseif(MSVC)
    foreach(target sifr_sha256 sifr-crypt)
        target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${SIFR_WARNINGS_AS_ERRORS}>:/WX>)
    endforeach()
endif()

install(TARGETS sifr-crypt sifr_sha256
    EXPORT sifr-crypt-targets
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT sifr-crypt-targets NAMESPACE sifr:: DESTINATION lib/cmake/sifr-crypt)

if(BUILD_TESTING)
    add_executable(sha256_test tests/sha256_test.cpp)
    target_link_libraries(sha256_test PRIVATE sifr::sha256)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(sha256_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
        if(SIFR_WARNINGS_AS_ERRORS)
            target_compile_options(sha256_test PRIVATE -Werror)
        endif()
    elseif(MSVC)
        target_compile_options(sha256_test PRIVATE /W4 $<$<BOOL:${SIFR_WARNINGS_AS_ERRORS}>:/WX>)
    endif()
    add_test(NAME unit COMMAND sha256_test)

    if(Python3_Interpreter_FOUND)
        add_test(NAME differential
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/differential.py $<TARGET_FILE:sifr-crypt>)
        add_test(NAME cli
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.py $<TARGET_FILE:sifr-crypt>)
    endif()
endif()
