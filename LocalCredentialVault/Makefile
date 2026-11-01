# Fallback Makefile for building without CMake (Linux / macOS / MSYS2)
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2 -Iinclude

# Detect system <sodium.h> vs bundled ABI-compatible header
ifeq ($(wildcard /usr/include/sodium.h),)
    CXXFLAGS += -Ithird_party/sodium_compat
endif

# Detect -lsodium vs direct shared object path
ifneq ($(wildcard /usr/lib/x86_64-linux-gnu/libsodium.so),)
    LDFLAGS := -lsodium
else ifneq ($(wildcard /usr/lib/x86_64-linux-gnu/libsodium.so.23),)
    LDFLAGS := /usr/lib/x86_64-linux-gnu/libsodium.so.23
else
    LDFLAGS := -lsodium
endif

CORE_SRCS := src/Credential.cpp \
             src/SecretBuffer.cpp \
             src/CryptoService.cpp \
             src/FileVaultStorage.cpp \
             src/CredentialVault.cpp

.PHONY: all test clean

all: build/vault_app build/test_vault

build/vault_app: src/main.cpp $(CORE_SRCS)
	@mkdir -p build data
	$(CXX) $(CXXFLAGS) src/main.cpp $(CORE_SRCS) $(LDFLAGS) -o build/vault_app

build/test_vault: tests/test_vault.cpp $(CORE_SRCS)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) tests/test_vault.cpp $(CORE_SRCS) $(LDFLAGS) -o build/test_vault

test: build/test_vault
	./build/test_vault

clean:
	rm -rf build
