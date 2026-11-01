#include "FileVaultStorage.h"

#include <fstream>
#include <system_error>

namespace vault {

FileVaultStorage::FileVaultStorage(std::filesystem::path filePath)
    : filePath_(std::move(filePath)), lastError_() {}

bool FileVaultStorage::exists() const {
    std::error_code ec;
    return std::filesystem::exists(filePath_, ec) &&
           std::filesystem::is_regular_file(filePath_, ec);
}

bool FileVaultStorage::createNew(const std::vector<unsigned char>& data) {
    if (exists()) {
        lastError_ = "A vault file already exists at '" + filePath_.string() +
                     "'. Refusing to overwrite existing vault.";
        return false;
    }
    return writeTempAndCommit(data);
}

bool FileVaultStorage::load(std::vector<unsigned char>& data) {
    data.clear();
    std::error_code ec;

    if (!std::filesystem::exists(filePath_, ec)) {
        lastError_ = "Vault file does not exist at '" + filePath_.string() + "'.";
        return false;
    }
    if (!std::filesystem::is_regular_file(filePath_, ec)) {
        lastError_ = "Vault path '" + filePath_.string() + "' is not a regular file.";
        return false;
    }

    const auto fileSize = std::filesystem::file_size(filePath_, ec);
    if (ec) {
        lastError_ = "Could not inspect vault file size: " + ec.message();
        return false;
    }
    if (fileSize < MIN_VAULT_FILE_SIZE) {
        lastError_ = "Vault file is truncated or smaller than the minimum valid header + tag size.";
        return false;
    }
    if (fileSize > MAX_VAULT_FILE_SIZE) {
        lastError_ = "Vault file exceeds the maximum permitted size of 1 MiB.";
        return false;
    }

    std::ifstream in(filePath_, std::ios::binary);
    if (!in.is_open()) {
        lastError_ = "Unable to open vault file for reading.";
        return false;
    }

    data.resize(static_cast<std::size_t>(fileSize));
    in.read(reinterpret_cast<char*>(data.data()),
            static_cast<std::streamsize>(fileSize));

    if (!in.good() && !in.eof()) {
        data.clear();
        lastError_ = "I/O error while reading encrypted vault file.";
        return false;
    }
    if (static_cast<std::size_t>(in.gcount()) != static_cast<std::size_t>(fileSize)) {
        data.clear();
        lastError_ = "Incomplete read while loading vault file.";
        return false;
    }

    lastError_.clear();
    return true;
}

bool FileVaultStorage::save(const std::vector<unsigned char>& data) {
    return writeTempAndCommit(data);
}

std::string FileVaultStorage::getLastError() const {
    return lastError_;
}

const std::filesystem::path& FileVaultStorage::getFilePath() const noexcept {
    return filePath_;
}

bool FileVaultStorage::writeTempAndCommit(const std::vector<unsigned char>& data) {
    if (data.size() < MIN_VAULT_FILE_SIZE || data.size() > MAX_VAULT_FILE_SIZE) {
        lastError_ = "Refusing to write invalid encrypted payload size.";
        return false;
    }

    std::error_code ec;
    const auto parentDir = filePath_.parent_path();
    if (!parentDir.empty() && !std::filesystem::exists(parentDir, ec)) {
        if (!std::filesystem::create_directories(parentDir, ec) && ec) {
            lastError_ = "Failed to create directory '" + parentDir.string() + "': " + ec.message();
            return false;
        }
    }

    // Write encrypted bytes to a sibling temporary file first
    std::filesystem::path tempPath = filePath_;
    tempPath += ".tmp";

    {
        std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            lastError_ = "Failed to open temporary file '" + tempPath.string() + "' for writing.";
            return false;
        }

        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        out.flush();

        if (!out.good()) {
            out.close();
            std::filesystem::remove(tempPath, ec);
            lastError_ = "Failed to write complete encrypted data to temporary file.";
            return false;
        }
        out.close();
        if (out.fail()) {
            std::filesystem::remove(tempPath, ec);
            lastError_ = "Failed to close temporary vault file cleanly.";
            return false;
        }
    }

    // Verify temporary file size before replacing the live vault file
    const auto writtenSize = std::filesystem::file_size(tempPath, ec);
    if (ec || writtenSize != data.size()) {
        std::filesystem::remove(tempPath, ec);
        lastError_ = "Temporary file verification failed prior to commit.";
        return false;
    }

    // Replace target file atomically (on POSIX rename replaces atomically;
    // on Windows if rename onto an existing target fails, fall back safely via backup)
    std::filesystem::rename(tempPath, filePath_, ec);
    if (ec) {
#ifdef _WIN32
        std::filesystem::path backupPath = filePath_;
        backupPath += ".bak";
        std::error_code winEc;
        std::filesystem::remove(backupPath, winEc);
        if (std::filesystem::exists(filePath_, winEc)) {
            std::filesystem::rename(filePath_, backupPath, winEc);
            if (winEc) {
                std::filesystem::remove(tempPath, winEc);
                lastError_ = "Failed to stage existing vault backup on Windows: " + winEc.message();
                return false;
            }
        }
        std::filesystem::rename(tempPath, filePath_, winEc);
        if (winEc) {
            // Restore original file from backup
            std::filesystem::rename(backupPath, filePath_, winEc);
            std::filesystem::remove(tempPath, winEc);
            lastError_ = "Failed to commit temporary vault file on Windows.";
            return false;
        }
        std::filesystem::remove(backupPath, winEc);
        ec.clear();
#else
        std::filesystem::remove(tempPath, ec);
        lastError_ = "Failed to commit temporary vault file into place.";
        return false;
#endif
    }

    lastError_.clear();
    return true;
}

} // namespace vault
