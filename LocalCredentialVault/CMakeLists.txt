cmake_minimum_required(VERSION 3.14)
project(LocalCredentialVault VERSION 1.0.0 LANGUAGES CXX)

# Enforce standard C++17 across all targets
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable helpful compiler warnings
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Locate libsodium via pkg-config or standard CMake find_library/find_path
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
endif()

if(NOT SODIUM_FOUND)
    find_path(SODIUM_INCLUDE_DIRS NAMES sodium.h)
    find_library(SODIUM_LIBRARIES NAMES sodium libsodium
                  PATHS /usr/lib/x86_64-linux-gnu /usr/local/lib /usr/lib)
    if(NOT SODIUM_LIBRARIES)
        find_file(SODIUM_LIBRARIES NAMES libsodium.so.23
                  PATHS /usr/lib/x86_64-linux-gnu /usr/lib)
    endif()
    if( NOT SODIUM_INCLUDE_DIRS )
        set(SODIUM_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sodium_compat")
    endif()
endif()

if(NOT SODIUM_LIBRARIES)
    message(FATAL_ERROR "libsodium library not found! Please install libsodium (see README.md).")
endif()

# Shared core library containing the 6 OOP architecture components
set(VAULT_CORE_SOURCES
    src/Credential.cpp
    src/SecretBuffer.cpp
    src/CryptoService.cpp
    src/FileVaultStorage.cpp
    src/CredentialVault.cpp
)

add_library(vault_core STATIC ${VAULT_CORE_SOURCES})
target_include_directories(vault_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(vault_core PUBLIC ${SODIUM_LIBRARIES})

# Main interactive console executable
add_executable(vault_app src/main.cpp)
target_link_libraries(vault_app PRIVATE vault_core)

# Automated verification test suite executable
enable_testing()
add_executable(test_vault tests/test_vault.cpp)
target_link_libraries(test_vault PRIVATE vault_core)
add_test(NAME VaultVerificationSuite COMMAND test_vault)
