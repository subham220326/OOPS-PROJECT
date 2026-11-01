#include "CryptoService.h"

#include <sodium.h>
#include <stdexcept>

namespace vault {

CryptoService::CryptoService() : initialized_(false) {
    initialize();
}

bool CryptoService::initialize() {
    if (initialized_) {
        return true;
    }
    if (sodium_init() < 0) {
        return false;
    }
    initialized_ = true;
    return true;
}

std::vector<unsigned char> CryptoService::generateSalt() const {
    if (!initialized_) {
        throw std::runtime_error("CryptoService is not initialized.");
    }
    std::vector<unsigned char> salt(SALT_BYTES, 0U);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

std::vector<unsigned char> CryptoService::generateNonce() const {
    if (!initialized_) {
        throw std::runtime_error("CryptoService is not initialized.");
    }
    std::vector<unsigned char> nonce(NONCE_BYTES, 0U);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

bool CryptoService::deriveKey(const std::string& masterPassword,
                              const std::vector<unsigned char>& salt,
                              std::uint32_t opslimit,
                              std::uint32_t memlimit,
                              SecretBuffer& outKey) const {
    if (!initialized_ || masterPassword.empty() || salt.size() != SALT_BYTES) {
        return false;
    }
    // Enforce the documented Argon2id interactive profile
    if (opslimit != DEFAULT_OPSLIMIT || memlimit != DEFAULT_MEMLIMIT) {
        return false;
    }

    outKey.resize(KEY_BYTES);
    const int rc = crypto_pwhash(
        outKey.data(),
        static_cast<unsigned long long>(outKey.size()),
        masterPassword.data(),
        static_cast<unsigned long long>(masterPassword.size()),
        salt.data(),
        static_cast<unsigned long long>(opslimit),
        static_cast<std::size_t>(memlimit),
        crypto_pwhash_ALG_ARGON2ID13);

    if (rc != 0) {
        outKey.clear();
        return false;
    }
    return true;
}

bool CryptoService::encrypt(const SecretBuffer& plaintext,
                            const std::vector<unsigned char>& associatedData,
                            const std::vector<unsigned char>& nonce,
                            const SecretBuffer& key,
                            std::vector<unsigned char>& outCiphertext) const {
    if (!initialized_ || nonce.size() != NONCE_BYTES || key.size() != KEY_BYTES) {
        return false;
    }

    outCiphertext.assign(plaintext.size() + TAG_BYTES, 0U);
    unsigned long long ciphertextLen = 0ULL;

    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        outCiphertext.data(),
        &ciphertextLen,
        plaintext.data(),
        static_cast<unsigned long long>(plaintext.size()),
        associatedData.empty() ? nullptr : associatedData.data(),
        static_cast<unsigned long long>(associatedData.size()),
        nullptr, // nsec is unused in libsodium AEAD
        nonce.data(),
        key.data());

    if (rc != 0) {
        outCiphertext.clear();
        return false;
    }
    outCiphertext.resize(static_cast<std::size_t>(ciphertextLen));
    return true;
}

bool CryptoService::decrypt(const std::vector<unsigned char>& ciphertext,
                            const std::vector<unsigned char>& associatedData,
                            const std::vector<unsigned char>& nonce,
                            const SecretBuffer& key,
                            SecretBuffer& outPlaintext) const {
    if (!initialized_ ||
        ciphertext.size() < TAG_BYTES ||
        nonce.size() != NONCE_BYTES ||
        key.size() != KEY_BYTES) {
        return false;
    }

    const std::size_t maxMessageSize = ciphertext.size() - TAG_BYTES;
    outPlaintext.resize(maxMessageSize);
    unsigned long long decryptedLen = 0ULL;

    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        outPlaintext.data(),
        &decryptedLen,
        nullptr, // nsec is unused in libsodium AEAD
        ciphertext.data(),
        static_cast<unsigned long long>(ciphertext.size()),
        associatedData.empty() ? nullptr : associatedData.data(),
        static_cast<unsigned long long>(associatedData.size()),
        nonce.data(),
        key.data());

    if (rc != 0) {
        outPlaintext.clear();
        return false;
    }
    return true;
}

} // namespace vault
