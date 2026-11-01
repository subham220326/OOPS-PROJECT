#ifndef CRYPTO_SERVICE_H
#define CRYPTO_SERVICE_H

#include "SecretBuffer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vault {

/**
 * @class CryptoService
 * @brief Encapsulates all cryptographic operations using libsodium.
 *
 * Responsibilities:
 * - Initialize libsodium safely.
 * - Generate cryptographically random salts (16 bytes) and nonces (24 bytes).
 * - Derive a 256-bit encryption key from a master password using Argon2id.
 * - Encrypt and authenticate serialized records using XChaCha20-Poly1305 IETF,
 *   binding the public file header as Associated Data (AAD).
 */
class CryptoService {
public:
    static constexpr std::size_t KEY_BYTES = 32;   // crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    static constexpr std::size_t SALT_BYTES = 16;  // crypto_pwhash_SALTBYTES
    static constexpr std::size_t NONCE_BYTES = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    static constexpr std::size_t TAG_BYTES = 16;   // crypto_aead_xchacha20poly1305_ietf_ABYTES

    static constexpr std::uint8_t KDF_ALG_ARGON2ID13 = 2; // crypto_pwhash_ALG_ARGON2ID13
    static constexpr std::uint32_t DEFAULT_OPSLIMIT = 2;  // crypto_pwhash_OPSLIMIT_INTERACTIVE
    static constexpr std::uint32_t DEFAULT_MEMLIMIT = 67108864U; // 64 MiB interactive profile

    CryptoService();
    ~CryptoService() = default;

    /**
     * @brief Initializes libsodium. Safe to call multiple times.
     */
    bool initialize();

    /**
     * @brief Generates a fresh 16-byte random salt using randombytes_buf().
     */
    std::vector<unsigned char> generateSalt() const;

    /**
     * @brief Generates a fresh 24-byte random nonce using randombytes_buf().
     */
    std::vector<unsigned char> generateNonce() const;

    /**
     * @brief Derives a 32-byte key from the master password and salt via Argon2id.
     */
    bool deriveKey(const std::string& masterPassword,
                   const std::vector<unsigned char>& salt,
                   std::uint32_t opslimit,
                   std::uint32_t memlimit,
                   SecretBuffer& outKey) const;

    /**
     * @brief Encrypts plaintext bytes with XChaCha20-Poly1305 and authenticates
     *        associatedData (the file header).
     */
    bool encrypt(const SecretBuffer& plaintext,
                 const std::vector<unsigned char>& associatedData,
                 const std::vector<unsigned char>& nonce,
                 const SecretBuffer& key,
                 std::vector<unsigned char>& outCiphertext) const;

    /**
     * @brief Verifies the Poly1305 tag over associatedData + ciphertext and
     *        decrypts the payload into outPlaintext.
     * @return false if the password/key is wrong or if any header/ciphertext
     *         byte was modified.
     */
    bool decrypt(const std::vector<unsigned char>& ciphertext,
                 const std::vector<unsigned char>& associatedData,
                 const std::vector<unsigned char>& nonce,
                 const SecretBuffer& key,
                 SecretBuffer& outPlaintext) const;

private:
    bool initialized_;
};

} // namespace vault

#endif // CRYPTO_SERVICE_H
