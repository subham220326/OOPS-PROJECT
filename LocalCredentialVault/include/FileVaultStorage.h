#ifndef FILE_VAULT_STORAGE_H
#define FILE_VAULT_STORAGE_H

#include "IVaultStorage.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace vault {

/**
 * @class FileVaultStorage
 * @brief Concrete local-disk implementation of IVaultStorage.
 *
 * OOP Concepts Demonstrated:
 * - Inheritance: Publicly inherits from the abstract class IVaultStorage.
 * - Runtime Polymorphism: Overrides load(), save(), createNew(), and exists().
 * - File Handling: Uses C++17 std::filesystem and binary std::ifstream /
 *   std::ofstream with temporary-file writes and checked replacement so a
 *   failed save never corrupts an existing vault file.
 */
class FileVaultStorage : public IVaultStorage {
public:
    static constexpr std::size_t MIN_VAULT_FILE_SIZE = 76;          // 56B header + 4B count + 16B tag
    static constexpr std::size_t MAX_VAULT_FILE_SIZE = 1024 * 1024; // 1 MiB safety ceiling

    explicit FileVaultStorage(std::filesystem::path filePath);
    ~FileVaultStorage() override = default;

    bool exists() const override;
    bool createNew(const std::vector<unsigned char>& data) override;
    bool load(std::vector<unsigned char>& data) override;
    bool save(const std::vector<unsigned char>& data) override;
    std::string getLastError() const override;

    const std::filesystem::path& getFilePath() const noexcept;

private:
    std::filesystem::path filePath_;
    mutable std::string lastError_;

    bool writeTempAndCommit(const std::vector<unsigned char>& data);
};

} // namespace vault

#endif // FILE_VAULT_STORAGE_H
