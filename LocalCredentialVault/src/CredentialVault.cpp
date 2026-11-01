#include "CredentialVault.h"

#include <sodium.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>

namespace vault {

namespace {

// Little-endian serialization helpers for cross-platform determinism
void writeU16LE(unsigned char* dst, std::uint16_t value) {
    dst[0] = static_cast<unsigned char>(value & 0xFFU);
    dst[1] = static_cast<unsigned char>((value >> 8U) & 0xFFU);
}

void writeU32LE(unsigned char* dst, std::uint32_t value) {
    dst[0] = static_cast<unsigned char>(value & 0xFFU);
    dst[1] = static_cast<unsigned char>((value >> 8U) & 0xFFU);
    dst[2] = static_cast<unsigned char>((value >> 16U) & 0xFFU);
    dst[3] = static_cast<unsigned char>((value >> 24U) & 0xFFU);
}

std::uint16_t readU16LE(const unsigned char* src) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(src[0]) |
        (static_cast<std::uint16_t>(src[1]) << 8U));
}

std::uint32_t readU32LE(const unsigned char* src) {
    return static_cast<std::uint32_t>(src[0]) |
           (static_cast<std::uint32_t>(src[1]) << 8U) |
           (static_cast<std::uint32_t>(src[2]) << 16U) |
           (static_cast<std::uint32_t>(src[3]) << 24U);
}

std::string toLowerCopy(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

} // namespace

CredentialVault::CredentialVault(std::unique_ptr<IVaultStorage> storage)
    : storage_(std::move(storage)),
      crypto_(),
      masterKey_(),
      salt_(),
      credentials_(),
      isUnlocked_(false),
      hasUnsavedChanges_(false),
      nextId_(1),
      lastError_() {
    if (!storage_) {
        throw std::invalid_argument("CredentialVault requires a valid IVaultStorage instance.");
    }
    if (!crypto_.initialize()) {
        throw std::runtime_error("Failed to initialize libsodium cryptographic subsystem.");
    }
}

CredentialVault::~CredentialVault() {
    lockVault();
}

bool CredentialVault::vaultExists() const {
    return storage_->exists();
}

bool CredentialVault::createVault(const std::string& masterPassword) {
    if (isUnlocked_) {
        lastError_ = "Lock the current session before creating a new vault.";
        return false;
    }
    if (masterPassword.empty()) {
        lastError_ = "Master password cannot be empty.";
        return false;
    }
    if (masterPassword.size() > MAX_MASTER_PASSWORD_LENGTH) {
        lastError_ = "Master password exceeds maximum length of 256 characters.";
        return false;
    }
    if (storage_->exists()) {
        lastError_ = "A vault already exists at the configured location. Unlock it instead.";
        return false;
    }

    try {
        std::vector<unsigned char> newSalt = crypto_.generateSalt();
        SecretBuffer derivedKey;
        if (!crypto_.deriveKey(masterPassword,
                               newSalt,
                               CryptoService::DEFAULT_OPSLIMIT,
                               CryptoService::DEFAULT_MEMLIMIT,
                               derivedKey)) {
            lastError_ = "Failed to derive encryption key using Argon2id.";
            return false;
        }

        // Prepare empty unlocked session state
        salt_ = std::move(newSalt);
        masterKey_ = std::move(derivedKey);
        credentials_.clear();
        nextId_ = 1;
        isUnlocked_ = true;
        hasUnsavedChanges_ = false;

        std::vector<unsigned char> encryptedBytes;
        if (!buildEncryptedVaultBytes(encryptedBytes)) {
            lockVault();
            return false;
        }

        if (!storage_->createNew(encryptedBytes)) {
            const std::string storageErr = storage_->getLastError();
            lockVault();
            lastError_ = storageErr.empty() ? "Failed to create new vault file." : storageErr;
            return false;
        }

        lastError_.clear();
        return true;
    } catch (const std::exception& ex) {
        lockVault();
        lastError_ = std::string("Exception during vault creation: ") + ex.what();
        return false;
    }
}

bool CredentialVault::unlockVault(const std::string& masterPassword) {
    if (isUnlocked_) {
        lastError_ = "Vault is already unlocked.";
        return false;
    }
    if (masterPassword.empty() || masterPassword.size() > MAX_MASTER_PASSWORD_LENGTH) {
        lastError_ = "Invalid master password length.";
        return false;
    }

    std::vector<unsigned char> fileBytes;
    if (!storage_->load(fileBytes)) {
        lastError_ = storage_->getLastError();
        return false;
    }

    // Step 1: Validate public header BEFORE running expensive Argon2id derivation
    if (fileBytes.size() < HEADER_SIZE + CryptoService::TAG_BYTES + 4U) {
        lastError_ = "Vault file is truncated or corrupted.";
        return false;
    }

    if (std::memcmp(fileBytes.data(), "LCV1", 4) != 0) {
        lastError_ = "Unrecognized file header magic (expected 'LCV1').";
        return false;
    }

    const std::uint8_t version = fileBytes[4];
    if (version != FORMAT_VERSION) {
        lastError_ = "Unsupported vault format version: " + std::to_string(version) + ".";
        return false;
    }

    const std::uint8_t kdfAlg = fileBytes[5];
    const std::uint16_t reserved = readU16LE(fileBytes.data() + 6);
    const std::uint32_t opslimit = readU32LE(fileBytes.data() + 8);
    const std::uint32_t memlimit = readU32LE(fileBytes.data() + 12);

    if (reserved != 0U ||
        kdfAlg != CryptoService::KDF_ALG_ARGON2ID13 ||
        opslimit != CryptoService::DEFAULT_OPSLIMIT ||
        memlimit != CryptoService::DEFAULT_MEMLIMIT) {
        lastError_ = "Unsupported or untrusted KDF parameters in vault header.";
        return false;
    }

    std::vector<unsigned char> fileSalt(
        fileBytes.begin() + 16,
        fileBytes.begin() + 16 + CryptoService::SALT_BYTES);
    std::vector<unsigned char> fileNonce(
        fileBytes.begin() + 32,
        fileBytes.begin() + 32 + CryptoService::NONCE_BYTES);
    std::vector<unsigned char> headerAAD(
        fileBytes.begin(),
        fileBytes.begin() + HEADER_SIZE);
    std::vector<unsigned char> ciphertext(
        fileBytes.begin() + HEADER_SIZE,
        fileBytes.end());

    // Step 2: Derive key with Argon2id
    SecretBuffer derivedKey;
    if (!crypto_.deriveKey(masterPassword, fileSalt, opslimit, memlimit, derivedKey)) {
        lastError_ = "Key derivation failed while unlocking vault.";
        return false;
    }

    // Step 3: Verify authentication tag over header + ciphertext and decrypt
    SecretBuffer decryptedPlaintext;
    if (!crypto_.decrypt(ciphertext, headerAAD, fileNonce, derivedKey, decryptedPlaintext)) {
        lastError_ = "Authentication failed: incorrect master password or tampered vault file.";
        return false;
    }

    // Step 4: Parse records only after cryptographic verification succeeds
    std::vector<Credential> parsedCredentials;
    int parsedNextId = 1;
    if (!deserializeCredentials(decryptedPlaintext, parsedCredentials, parsedNextId)) {
        lastError_ = "Decrypted vault payload failed structural validation.";
        return false;
    }

    // Commit unlocked state
    salt_ = std::move(fileSalt);
    masterKey_ = std::move(derivedKey);
    credentials_ = std::move(parsedCredentials);
    nextId_ = parsedNextId;
    isUnlocked_ = true;
    hasUnsavedChanges_ = false;
    lastError_.clear();
    return true;
}

bool CredentialVault::saveChanges() {
    if (!ensureUnlocked()) {
        return false;
    }

    std::vector<unsigned char> encryptedBytes;
    if (!buildEncryptedVaultBytes(encryptedBytes)) {
        return false;
    }

    if (!storage_->save(encryptedBytes)) {
        lastError_ = storage_->getLastError();
        if (lastError_.empty()) {
            lastError_ = "Failed to save encrypted vault to disk.";
        }
        return false;
    }

    hasUnsavedChanges_ = false;
    lastError_.clear();
    return true;
}

void CredentialVault::lockVault() {
    credentials_.clear();
    masterKey_.clear();
    if (!salt_.empty()) {
        std::fill(salt_.begin(), salt_.end(), 0U);
        salt_.clear();
    }
    isUnlocked_ = false;
    hasUnsavedChanges_ = false;
    nextId_ = 1;
}

bool CredentialVault::isUnlocked() const noexcept {
    return isUnlocked_;
}

bool CredentialVault::hasUnsavedChanges() const noexcept {
    return hasUnsavedChanges_;
}

std::size_t CredentialVault::getCredentialCount() const {
    if (!isUnlocked_) {
        return 0;
    }
    return credentials_.size();
}

const std::string& CredentialVault::getLastError() const noexcept {
    return lastError_;
}

bool CredentialVault::addCredential(const std::string& label,
                                    const std::string& username,
                                    const std::string& password) {
    if (!ensureUnlocked()) {
        return false;
    }
    if (credentials_.size() >= MAX_RECORDS) {
        lastError_ = "Vault has reached the maximum capacity of " +
                     std::to_string(MAX_RECORDS) + " credentials.";
        return false;
    }

    try {
        Credential::validateFields(label, username, password);
        if (isDuplicateLabel(label)) {
            lastError_ = "A credential with the label '" + label + "' already exists.";
            return false;
        }

        Credential record(nextId_++, label, username, password);
        credentials_.push_back(std::move(record));
        hasUnsavedChanges_ = true;
        lastError_.clear();
        return true;
    } catch (const std::exception& ex) {
        lastError_ = ex.what();
        return false;
    }
}

std::vector<Credential> CredentialVault::getAllCredentials() const {
    if (!ensureUnlocked()) {
        return {};
    }
    return credentials_;
}

std::optional<Credential> CredentialVault::getCredentialById(int id) const {
    if (!ensureUnlocked()) {
        return std::nullopt;
    }
    for (const auto& cred : credentials_) {
        if (cred.getId() == id) {
            lastError_.clear();
            return cred;
        }
    }
    lastError_ = "No credential found with ID " + std::to_string(id) + ".";
    return std::nullopt;
}

std::vector<Credential> CredentialVault::searchCredentials(const std::string& query) const {
    if (!ensureUnlocked()) {
        return {};
    }
    if (query.empty()) {
        lastError_ = "Search query cannot be empty.";
        return {};
    }

    const std::string needle = toLowerCopy(query);
    std::vector<Credential> matches;
    for (const auto& cred : credentials_) {
        const std::string labelLower = toLowerCopy(cred.getLabel());
        const std::string userLower = toLowerCopy(cred.getUsername());
        if (labelLower.find(needle) != std::string::npos ||
            userLower.find(needle) != std::string::npos) {
            matches.push_back(cred);
        }
    }
    lastError_.clear();
    return matches;
}

bool CredentialVault::editCredential(int id,
                                     const std::string& newLabel,
                                     const std::string& newUsername,
                                     const std::string& newPassword) {
    if (!ensureUnlocked()) {
        return false;
    }

    for (auto& cred : credentials_) {
        if (cred.getId() == id) {
            try {
                Credential::validateFields(newLabel, newUsername, newPassword);
                if (isDuplicateLabel(newLabel, id)) {
                    lastError_ = "Another credential already uses the label '" + newLabel + "'.";
                    return false;
                }
                cred.setLabel(newLabel);
                cred.setUsername(newUsername);
                cred.setPassword(newPassword);
                hasUnsavedChanges_ = true;
                lastError_.clear();
                return true;
            } catch (const std::exception& ex) {
                lastError_ = ex.what();
                return false;
            }
        }
    }

    lastError_ = "No credential found with ID " + std::to_string(id) + ".";
    return false;
}

bool CredentialVault::deleteCredential(int id) {
    if (!ensureUnlocked()) {
        return false;
    }

    for (auto it = credentials_.begin(); it != credentials_.end(); ++it) {
        if (it->getId() == id) {
            credentials_.erase(it);
            hasUnsavedChanges_ = true;
            lastError_.clear();
            return true;
        }
    }

    lastError_ = "No credential found with ID " + std::to_string(id) + ".";
    return false;
}

bool CredentialVault::ensureUnlocked() const {
    if (!isUnlocked_ || masterKey_.empty()) {
        lastError_ = "Operation denied: the vault is currently LOCKED.";
        return false;
    }
    return true;
}

bool CredentialVault::isDuplicateLabel(const std::string& label, int ignoreId) const {
    const std::string target = toLowerCopy(label);
    for (const auto& cred : credentials_) {
        if (cred.getId() != ignoreId && toLowerCopy(cred.getLabel()) == target) {
            return true;
        }
    }
    return false;
}

bool CredentialVault::serializeCredentials(SecretBuffer& outBuffer) const {
    if (credentials_.size() > MAX_RECORDS) {
        lastError_ = "Too many records to serialize.";
        return false;
    }

    std::size_t totalBytes = 4U; // 4-byte record_count
    for (const auto& cred : credentials_) {
        totalBytes += 4U; // id (uint32_t)
        totalBytes += 2U + cred.getLabel().size();
        totalBytes += 2U + cred.getUsername().size();
        totalBytes += 2U + cred.getPassword().size();
    }

    outBuffer.resize(totalBytes);
    unsigned char* ptr = outBuffer.data();

    writeU32LE(ptr, static_cast<std::uint32_t>(credentials_.size()));
    ptr += 4U;

    for (const auto& cred : credentials_) {
        writeU32LE(ptr, static_cast<std::uint32_t>(cred.getId()));
        ptr += 4U;

        const std::string& lbl = cred.getLabel();
        writeU16LE(ptr, static_cast<std::uint16_t>(lbl.size()));
        ptr += 2U;
        std::memcpy(ptr, lbl.data(), lbl.size());
        ptr += lbl.size();

        const std::string& usr = cred.getUsername();
        writeU16LE(ptr, static_cast<std::uint16_t>(usr.size()));
        ptr += 2U;
        std::memcpy(ptr, usr.data(), usr.size());
        ptr += usr.size();

        const std::string& pwd = cred.getPassword();
        writeU16LE(ptr, static_cast<std::uint16_t>(pwd.size()));
        ptr += 2U;
        std::memcpy(ptr, pwd.data(), pwd.size());
        ptr += pwd.size();
    }

    return true;
}

bool CredentialVault::deserializeCredentials(const SecretBuffer& inBuffer,
                                             std::vector<Credential>& outCredentials,
                                             int& outNextId) {
    outCredentials.clear();
    outNextId = 1;

    if (inBuffer.size() < 4U) {
        return false;
    }

    const unsigned char* ptr = inBuffer.data();
    std::size_t remaining = inBuffer.size();

    const std::uint32_t count = readU32LE(ptr);
    ptr += 4U;
    remaining -= 4U;

    if (count > MAX_RECORDS) {
        return false;
    }

    outCredentials.reserve(count);
    int maxId = 0;

    for (std::uint32_t i = 0; i < count; ++i) {
        if (remaining < 4U + 2U + 2U + 2U) {
            outCredentials.clear();
            return false;
        }

        const std::uint32_t rawId = readU32LE(ptr);
        ptr += 4U;
        remaining -= 4U;
        if (rawId == 0U || rawId > 1000000U) {
            outCredentials.clear();
            return false;
        }

        const std::uint16_t labelLen = readU16LE(ptr);
        ptr += 2U;
        remaining -= 2U;
        if (labelLen == 0U || labelLen > Credential::MAX_LABEL_LENGTH || remaining < labelLen + 4U) {
            outCredentials.clear();
            return false;
        }
        std::string label(reinterpret_cast<const char*>(ptr), labelLen);
        ptr += labelLen;
        remaining -= labelLen;

        const std::uint16_t userLen = readU16LE(ptr);
        ptr += 2U;
        remaining -= 2U;
        if (userLen == 0U || userLen > Credential::MAX_USERNAME_LENGTH || remaining < userLen + 2U) {
            outCredentials.clear();
            return false;
        }
        std::string username(reinterpret_cast<const char*>(ptr), userLen);
        ptr += userLen;
        remaining -= userLen;

        const std::uint16_t passLen = readU16LE(ptr);
        ptr += 2U;
        remaining -= 2U;
        if (passLen == 0U || passLen > Credential::MAX_PASSWORD_LENGTH || remaining < passLen) {
            outCredentials.clear();
            return false;
        }
        std::string password(reinterpret_cast<const char*>(ptr), passLen);
        ptr += passLen;
        remaining -= passLen;

        const int id = static_cast<int>(rawId);
        // Reject duplicate IDs or duplicate labels in serialized stream
        for (const auto& existing : outCredentials) {
            if (existing.getId() == id ||
                toLowerCopy(existing.getLabel()) == toLowerCopy(label)) {
                outCredentials.clear();
                return false;
            }
        }

        outCredentials.emplace_back(id, label, username, password);
        if (id > maxId) {
            maxId = id;
        }
        if (!password.empty()) {
            sodium_memzero(&password[0], password.size());
        }
    }

    if (remaining != 0U) {
        outCredentials.clear();
        return false;
    }

    outNextId = maxId + 1;
    return true;
}

bool CredentialVault::buildEncryptedVaultBytes(std::vector<unsigned char>& outFileBytes) {
    SecretBuffer plaintext;
    if (!serializeCredentials(plaintext)) {
        return false;
    }

    // Generate a fresh 24-byte random nonce on every save
    const std::vector<unsigned char> nonce = crypto_.generateNonce();

    // Construct the 56-byte public header (bound as Associated Data / AAD)
    std::vector<unsigned char> header(HEADER_SIZE, 0U);
    std::memcpy(header.data(), "LCV1", 4);
    header[4] = FORMAT_VERSION;
    header[5] = CryptoService::KDF_ALG_ARGON2ID13;
    writeU16LE(header.data() + 6, 0U);
    writeU32LE(header.data() + 8, CryptoService::DEFAULT_OPSLIMIT);
    writeU32LE(header.data() + 12, CryptoService::DEFAULT_MEMLIMIT);
    std::memcpy(header.data() + 16, salt_.data(), CryptoService::SALT_BYTES);
    std::memcpy(header.data() + 32, nonce.data(), CryptoService::NONCE_BYTES);

    std::vector<unsigned char> ciphertext;
    if (!crypto_.encrypt(plaintext, header, nonce, masterKey_, ciphertext)) {
        lastError_ = "Failed to encrypt credential collection with XChaCha20-Poly1305.";
        return false;
    }

    outFileBytes.clear();
    outFileBytes.reserve(header.size() + ciphertext.size());
    outFileBytes.insert(outFileBytes.end(), header.begin(), header.end());
    outFileBytes.insert(outFileBytes.end(), ciphertext.begin(), ciphertext.end());
    return true;
}

} // namespace vault
