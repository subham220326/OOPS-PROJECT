#include "Credential.h"
#include "CredentialVault.h"
#include "CryptoService.h"
#include "FileVaultStorage.h"
#include "IVaultStorage.h"
#include "SecretBuffer.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

void reportTest(const std::string& name, bool passed, const std::string& detail = "") {
    if (passed) {
        ++g_passed;
        std::cout << "[PASS] " << name;
        if (!detail.empty()) {
            std::cout << " — " << detail;
        }
        std::cout << "\n";
    } else {
        ++g_failed;
        std::cout << "[FAIL] " << name;
        if (!detail.empty()) {
            std::cout << " — " << detail;
        }
        std::cout << "\n";
    }
}

/**
 * @class FailingSaveDecorator
 * @brief Test helper inheriting from IVaultStorage to simulate a disk failure
 *        during save() while delegating other operations to FileVaultStorage.
 */
class FailingSaveDecorator : public vault::IVaultStorage {
public:
    explicit FailingSaveDecorator(std::filesystem::path path)
        : inner_(std::move(path)), failNextSave_(false) {}

    void setFailNextSave(bool fail) { failNextSave_ = fail; }

    bool exists() const override { return inner_.exists(); }
    bool createNew(const std::vector<unsigned char>& data) override {
        return inner_.createNew(data);
    }
    bool load(std::vector<unsigned char>& data) override {
        return inner_.load(data);
    }
    bool save(const std::vector<unsigned char>& data) override {
        if (failNextSave_) {
            return false;
        }
        return inner_.save(data);
    }
    std::string getLastError() const override {
        if (failNextSave_) {
            return "Simulated disk write failure during commit.";
        }
        return inner_.getLastError();
    }

private:
    vault::FileVaultStorage inner_;
    bool failNextSave_;
};

std::vector<unsigned char> readRawFile(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}

void writeRawFile(const std::filesystem::path& p, const std::vector<unsigned char>& bytes) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

} // namespace

int main() {
    std::cout << "==========================================================\n"
              << "   LOCAL CREDENTIAL VAULT — AUTOMATED VERIFICATION SUITE\n"
              << "==========================================================\n\n";

    const std::filesystem::path testDir = std::filesystem::temp_directory_path() / "lcv_test_suite";
    std::error_code ec;
    std::filesystem::remove_all(testDir, ec);
    std::filesystem::create_directories(testDir, ec);

    const std::filesystem::path vaultFile = testDir / "vault.dat";
    const std::string masterPass = "CorrectHorse!Battery99";

    // -----------------------------------------------------------------------
    // Test 1: Vault Creation (including refusal to overwrite an existing vault)
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v(std::move(storage));
        const bool created = v.createVault(masterPass);
        const bool existsOnDisk = std::filesystem::exists(vaultFile);
        v.lockVault();

        // Attempting to create again over an existing file must fail safely
        auto storage2 = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v2(std::move(storage2));
        const bool overwriteBlocked = !v2.createVault("AnotherPassword123");

        reportTest("Test 1: Vault Creation",
                   created && existsOnDisk && overwriteBlocked,
                   "Created encrypted empty vault and prevented accidental overwrite");
    }

    // -----------------------------------------------------------------------
    // Test 2: Correct Master Password
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v(std::move(storage));
        const bool unlocked = v.unlockVault(masterPass);
        reportTest("Test 2: Correct Master Password",
                   unlocked && v.isUnlocked() && v.getCredentialCount() == 0,
                   "Unlocked empty vault with valid master password");
    }

    // -----------------------------------------------------------------------
    // Test 3: Incorrect Master Password
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v(std::move(storage));
        const bool unlocked = v.unlockVault("WrongMasterPassword!");
        reportTest("Test 3: Incorrect Master Password",
                   !unlocked && !v.isUnlocked() && v.getAllCredentials().empty(),
                   "Rejected wrong password and kept vault LOCKED");
    }

    // -----------------------------------------------------------------------
    // Test 4: Add Credential (including spaces, punctuation, max sizes, & duplicate rejection)
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v(std::move(storage));
        v.unlockVault(masterPass);

        const bool add1 = v.addCredential("Google Workspace", "subham.example@gmail.com", "G00gle$ecret#2026!");
        const bool add2 = v.addCredential("GitHub", "developer_subham", "Gh_Token_!@#987");
        const bool add3 = v.addCredential("Instagram", "user_example", "Insta*Pass*42");
        // Duplicate label attempt (case-insensitive) should be rejected
        const bool duplicateRejected = !v.addCredential("github", "another_user", "Pass1234");
        const bool saved = v.saveChanges();

        reportTest("Test 4: Add Credential",
                   add1 && add2 && add3 && duplicateRejected && saved && v.getCredentialCount() == 3,
                   "Added 3 fictional credentials, rejected duplicate label, and saved");
    }

    // -----------------------------------------------------------------------
    // Test 5: Edit Credential (and Search Credentials)
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v(std::move(storage));
        v.unlockVault(masterPass);

        const auto searchMatches = v.searchCredentials("GitHub");
        const bool searchFound = (searchMatches.size() == 1 && searchMatches[0].getUsername() == "developer_subham");

        const bool edited = v.editCredential(2, "GitHub Enterprise", "subham_dev_pro", "Updated_Gh_Pass#2026");
        const auto updatedRec = v.getCredentialById(2);
        const bool editVerified = updatedRec.has_value() &&
                                  updatedRec->getLabel() == "GitHub Enterprise" &&
                                  updatedRec->getUsername() == "subham_dev_pro" &&
                                  updatedRec->getPassword() == "Updated_Gh_Pass#2026";
        const bool saved = v.saveChanges();

        reportTest("Test 5: Edit & Search Credential",
                   searchFound && edited && editVerified && saved,
                   "Searched and updated record #2 in memory and saved changes");
    }

    // -----------------------------------------------------------------------
    // Test 6: Delete Credential
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault v(std::move(storage));
        v.unlockVault(masterPass);

        const std::vector<unsigned char> beforeSaveBytes = readRawFile(vaultFile);
        const bool deleted = v.deleteCredential(3); // Delete Instagram
        const bool missingNow = !v.getCredentialById(3).has_value();
        const bool saved = v.saveChanges();
        const std::vector<unsigned char> afterSaveBytes = readRawFile(vaultFile);

        // Verify that the 24-byte nonce at offset [32..56) changed across saves
        const bool freshNonceUsed =
            beforeSaveBytes.size() >= 56 && afterSaveBytes.size() >= 56 &&
            std::memcmp(beforeSaveBytes.data() + 32, afterSaveBytes.data() + 32, 24) != 0;

        reportTest("Test 6: Delete Credential",
                   deleted && missingNow && saved && v.getCredentialCount() == 2 && freshNonceUsed,
                   "Deleted record #3 and verified fresh random nonce on re-save");
    }

    // -----------------------------------------------------------------------
    // Test 7: Persistence Across Restart
    // -----------------------------------------------------------------------
    {
        auto storage = std::make_unique<vault::FileVaultStorage>(vaultFile);
        vault::CredentialVault reopenedVault(std::move(storage));
        const bool unlocked = reopenedVault.unlockVault(masterPass);
        const auto all = reopenedVault.getAllCredentials();

        const bool recordsMatch =
            unlocked && all.size() == 2 &&
            all[0].getId() == 1 && all[0].getLabel() == "Google Workspace" &&
            all[0].getPassword() == "G00gle$ecret#2026!" &&
            all[1].getId() == 2 && all[1].getLabel() == "GitHub Enterprise" &&
            all[1].getPassword() == "Updated_Gh_Pass#2026";

        reportTest("Test 7: Persistence",
                   recordsMatch,
                   "Reopened vault in a fresh instance and verified surviving records");
    }

    // -----------------------------------------------------------------------
    // Test 8: Encrypted File (No Plaintext Leakage on Disk)
    // -----------------------------------------------------------------------
    {
        const std::vector<unsigned char> rawBytes = readRawFile(vaultFile);
        const std::string rawAsString(reinterpret_cast<const char*>(rawBytes.data()), rawBytes.size());

        const bool noMasterPass = (rawAsString.find(masterPass) == std::string::npos);
        const bool noCredPass1 = (rawAsString.find("G00gle$ecret#2026!") == std::string::npos);
        const bool noCredPass2 = (rawAsString.find("Updated_Gh_Pass#2026") == std::string::npos);
        const bool noUsername = (rawAsString.find("subham.example@gmail.com") == std::string::npos);

        reportTest("Test 8: Encrypted File",
                   noMasterPass && noCredPass1 && noCredPass2 && noUsername,
                   "Verified master password, usernames, and passwords do not appear in plaintext");
    }

    // -----------------------------------------------------------------------
    // Test 9: Tampering Detection (Ciphertext & Authenticated Header AAD)
    // -----------------------------------------------------------------------
    {
        const std::vector<unsigned char> validBytes = readRawFile(vaultFile);
        const std::filesystem::path tamperedPath = testDir / "tampered.dat";

        // 9a: Flip 1 bit inside the encrypted payload
        std::vector<unsigned char> badCipher = validBytes;
        badCipher[badCipher.size() - 20] ^= 0x01U;
        writeRawFile(tamperedPath, badCipher);

        vault::CredentialVault vCipher(std::make_unique<vault::FileVaultStorage>(tamperedPath));
        const bool cipherRejected = !vCipher.unlockVault(masterPass) && !vCipher.isUnlocked();

        // 9b: Flip 1 bit in the authenticated header nonce/AAD
        std::vector<unsigned char> badHeader = validBytes;
        badHeader[35] ^= 0x01U;
        writeRawFile(tamperedPath, badHeader);

        vault::CredentialVault vHeader(std::make_unique<vault::FileVaultStorage>(tamperedPath));
        const bool headerRejected = !vHeader.unlockVault(masterPass) && !vHeader.isUnlocked();

        reportTest("Test 9: Tampering Detection",
                   cipherRejected && headerRejected,
                   "Rejected both ciphertext tampering and authenticated header tampering");
    }

    // -----------------------------------------------------------------------
    // Test 10: File Handling (Truncated, Malformed Header, Maximum Field Bounds, Failed Save)
    // -----------------------------------------------------------------------
    {
        // 10a: Truncated file
        const std::filesystem::path truncatedPath = testDir / "truncated.dat";
        writeRawFile(truncatedPath, std::vector<unsigned char>{'L', 'C', 'V', '1', 1, 2});
        vault::CredentialVault vTrunc(std::make_unique<vault::FileVaultStorage>(truncatedPath));
        const bool truncRejected = !vTrunc.unlockVault(masterPass);

        // 10b: Unsupported version in header (rejected prior to KDF)
        std::vector<unsigned char> badVer = readRawFile(vaultFile);
        badVer[4] = 99; // Invalid version
        const std::filesystem::path badVerPath = testDir / "bad_version.dat";
        writeRawFile(badVerPath, badVer);
        vault::CredentialVault vVer(std::make_unique<vault::FileVaultStorage>(badVerPath));
        const bool verRejected = !vVer.unlockVault(masterPass);

        // 10c: Field boundary validation (max permitted sizes succeed, oversized fails)
        auto storage = std::make_unique<FailingSaveDecorator>(vaultFile);
        FailingSaveDecorator* rawDecorator = storage.get();
        vault::CredentialVault vBounds(std::move(storage));
        vBounds.unlockVault(masterPass);

        const std::string maxLabel(vault::Credential::MAX_LABEL_LENGTH, 'L');
        const std::string maxUser(vault::Credential::MAX_USERNAME_LENGTH, 'U');
        const std::string maxPass(vault::Credential::MAX_PASSWORD_LENGTH, 'P');
        const bool maxAllowed = vBounds.addCredential(maxLabel, maxUser, maxPass);
        const bool overLabelRejected = !vBounds.addCredential(maxLabel + "X", "user", "pass");

        // 10d: Simulate a failed save attempt and confirm previous file on disk is intact
        rawDecorator->setFailNextSave(true);
        const bool failedSaveReported = !vBounds.saveChanges();
        const bool sessionStillHasPending = vBounds.hasUnsavedChanges() && (vBounds.getCredentialCount() == 3);

        // Reopen the disk file separately and verify it still holds the 2 earlier records
        vault::CredentialVault vVerifyDisk(std::make_unique<vault::FileVaultStorage>(vaultFile));
        const bool diskIntact = vVerifyDisk.unlockVault(masterPass) && (vVerifyDisk.getCredentialCount() == 2);

        reportTest("Test 10: File Handling & Failed Save Recovery",
                   truncRejected && verRejected && maxAllowed && overLabelRejected &&
                       failedSaveReported && sessionStillHasPending && diskIntact,
                   "Rejected truncated/bad-version files, validated max bounds, and preserved original file on failed save");
    }

    // -----------------------------------------------------------------------
    // Test 11: Locked-State Protection
    // -----------------------------------------------------------------------
    {
        vault::CredentialVault v(std::make_unique<vault::FileVaultStorage>(vaultFile));
        const bool cannotAdd = !v.addCredential("Netflix", "user@net.com", "Pass123");
        const bool cannotEdit = !v.editCredential(1, "Netflix", "user@net.com", "Pass123");
        const bool cannotDelete = !v.deleteCredential(1);
        const bool cannotSave = !v.saveChanges();
        const bool cannotView = v.getAllCredentials().empty() && !v.getCredentialById(1).has_value();
        const bool cannotSearch = v.searchCredentials("Google").empty();

        reportTest("Test 11: Locked-State Protection",
                   !v.isUnlocked() && cannotAdd && cannotEdit && cannotDelete &&
                       cannotSave && cannotView && cannotSearch,
                   "Blocked add, edit, delete, save, view, and search while vault is LOCKED");
    }

    // -----------------------------------------------------------------------
    // Test 12: Unsaved Changes Tracking (Save vs. Discard Workflows)
    // -----------------------------------------------------------------------
    {
        // Workflow A: Modify -> Discard (lock without saving) -> Reopen -> Verify discarded
        {
            vault::CredentialVault v(std::make_unique<vault::FileVaultStorage>(vaultFile));
            v.unlockVault(masterPass);
            const bool cleanInitially = !v.hasUnsavedChanges();
            v.addCredential("TemporarySite", "temp_user", "temp_pass");
            const bool dirtyAfterAdd = v.hasUnsavedChanges();
            // Discard changes and lock
            v.lockVault();
            const bool cleanAfterLock = !v.isUnlocked() && !v.hasUnsavedChanges();

            // Reopen and confirm TemporarySite was NOT saved
            v.unlockVault(masterPass);
            const bool discardVerified = cleanInitially && dirtyAfterAdd && cleanAfterLock &&
                                         (v.getCredentialCount() == 2);

            // Workflow B: Modify -> Save and Lock -> Reopen -> Verify persisted
            v.addCredential("LinkedIn", "subham_in", "L1nkedIn#Pass");
            const bool dirtyAgain = v.hasUnsavedChanges();
            const bool savedOk = v.saveChanges();
            const bool cleanAfterSave = !v.hasUnsavedChanges();
            v.lockVault();

            v.unlockVault(masterPass);
            const bool saveVerified = dirtyAgain && savedOk && cleanAfterSave &&
                                      (v.getCredentialCount() == 3);

            reportTest("Test 12: Unsaved Changes (Save & Discard)",
                       discardVerified && saveVerified,
                       "Verified dirty-state tracking across Discard-and-Lock and Save-and-Lock");
        }
    }

    std::filesystem::remove_all(testDir, ec);

    std::cout << "\n----------------------------------------------------------\n"
              << "Test Summary: " << g_passed << " passed, " << g_failed << " failed.\n"
              << "==========================================================\n";

    return (g_failed == 0) ? 0 : 1;
}
