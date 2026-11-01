#ifndef CREDENTIAL_VAULT_H
#define CREDENTIAL_VAULT_H

#include "Credential.h"
#include "CryptoService.h"
#include "IVaultStorage.h"
#include "SecretBuffer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vault {

/**
 * @class CredentialVault
 * @brief Main application controller managing session state, in-memory
 *        credentials, binary serialization, encryption, and storage commits.
 *
 * OOP Concepts Demonstrated:
 * - Composition: Owns std::vector<Credential>, CryptoService, SecretBuffer,
 *   and std::unique_ptr<IVaultStorage>.
 * - Runtime Polymorphism: Performs all load/save calls through the abstract
 *   IVaultStorage interface pointer.
 * - Encapsulation & State Gating: Enforces LOCKED vs. UNLOCKED state on every
 *   credential operation and tracks pending unsaved changes.
 */
class CredentialVault {
public:
    static constexpr std::size_t HEADER_SIZE = 56;
    static constexpr std::uint8_t FORMAT_VERSION = 1;
    static constexpr std::size_t MAX_RECORDS = 1000;
    static constexpr std::size_t MAX_MASTER_PASSWORD_LENGTH = 256;

    /**
     * @brief Constructs a CredentialVault taking ownership of an IVaultStorage
     *        implementation via std::unique_ptr.
     */
    explicit CredentialVault(std::unique_ptr<IVaultStorage> storage);

    /**
     * @brief Destructor locks the vault and clears all sensitive memory.
     */
    ~CredentialVault();

    CredentialVault(const CredentialVault&) = delete;
    CredentialVault& operator=(const CredentialVault&) = delete;

    // Session & persistence operations
    bool vaultExists() const;
    bool createVault(const std::string& masterPassword);
    bool unlockVault(const std::string& masterPassword);
    bool saveChanges();
    void lockVault();

    // State inspection
    bool isUnlocked() const noexcept;
    bool hasUnsavedChanges() const noexcept;
    std::size_t getCredentialCount() const;
    const std::string& getLastError() const noexcept;

    // Controlled credential management (only available while UNLOCKED)
    bool addCredential(const std::string& label,
                       const std::string& username,
                       const std::string& password);

    std::vector<Credential> getAllCredentials() const;
    std::optional<Credential> getCredentialById(int id) const;
    std::vector<Credential> searchCredentials(const std::string& query) const;

    bool editCredential(int id,
                        const std::string& newLabel,
                        const std::string& newUsername,
                        const std::string& newPassword);

    bool deleteCredential(int id);

private:
    std::unique_ptr<IVaultStorage> storage_;
    CryptoService crypto_;
    SecretBuffer masterKey_;
    std::vector<unsigned char> salt_;
    std::vector<Credential> credentials_;
    bool isUnlocked_;
    bool hasUnsavedChanges_;
    int nextId_;
    mutable std::string lastError_;

    bool ensureUnlocked() const;
    bool isDuplicateLabel(const std::string& label, int ignoreId = -1) const;

    bool serializeCredentials(SecretBuffer& outBuffer) const;
    bool deserializeCredentials(const SecretBuffer& inBuffer,
                                std::vector<Credential>& outCredentials,
                                int& outNextId);

    bool buildEncryptedVaultBytes(std::vector<unsigned char>& outFileBytes);
};

} // namespace vault

#endif // CREDENTIAL_VAULT_H
