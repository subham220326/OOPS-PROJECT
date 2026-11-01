#ifndef IVAULT_STORAGE_H
#define IVAULT_STORAGE_H

#include <string>
#include <vector>

namespace vault {

/**
 * @class IVaultStorage
 * @brief Abstract base class defining the persistence interface for a vault.
 *
 * OOP Concepts Demonstrated:
 * - Abstraction: Hides physical storage mechanics behind pure virtual methods.
 * - Polymorphism: Allows CredentialVault to interact with any storage backend
 *   through a base-class smart pointer (std::unique_ptr<IVaultStorage>).
 */
class IVaultStorage {
public:
    virtual ~IVaultStorage() = default;

    /**
     * @brief Checks whether a vault already exists in storage.
     */
    virtual bool exists() const = 0;

    /**
     * @brief Creates a brand-new vault without overwriting an existing one.
     */
    virtual bool createNew(const std::vector<unsigned char>& data) = 0;

    /**
     * @brief Loads raw encrypted bytes from storage into data.
     */
    virtual bool load(std::vector<unsigned char>& data) = 0;

    /**
     * @brief Saves raw encrypted bytes to storage using an atomic/checked commit.
     */
    virtual bool save(const std::vector<unsigned char>& data) = 0;

    /**
     * @brief Returns a human-readable description of the most recent storage error.
     */
    virtual std::string getLastError() const = 0;
};

} // namespace vault

#endif // IVAULT_STORAGE_H
