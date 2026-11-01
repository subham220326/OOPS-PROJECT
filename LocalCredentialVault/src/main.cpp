#include "CredentialVault.h"
#include "FileVaultStorage.h"

#include <sodium.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

/**
 * @brief Platform-isolated helper for reading a password without echoing
 *        characters to the terminal (displays '*' per character on Windows
 *        and hides input cleanly on POSIX terminals, with non-TTY fallback).
 */
std::string readHiddenPassword(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string password;

#ifdef _WIN32
    while (true) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n' || ch == EOF) {
            std::cout << "\n";
            break;
        } else if (ch == '\b' || ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        } else if (ch == 3) { // Ctrl+C
            std::cout << "\n";
            break;
        } else if (ch >= 32 && ch <= 126) {
            password.push_back(static_cast<char>(ch));
            std::cout << '*' << std::flush;
        }
    }
#else
    if (isatty(STDIN_FILENO)) {
        struct termios oldt {};
        if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
            struct termios newt = oldt;
            newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            std::getline(std::cin, password);
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            std::cout << "\n";
            return password;
        }
    }
    std::getline(std::cin, password);
    if (!password.empty() && password.back() == '\r') {
        password.pop_back();
    }
#endif
    return password;
}

void wipeString(std::string& s) {
    if (!s.empty()) {
        sodium_memzero(&s[0], s.size());
        s.clear();
    }
}

std::string readLineTrimmed(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        return "";
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    const auto first = line.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = line.find_last_not_of(" \t");
    return line.substr(first, last - first + 1);
}

int readMenuChoice(const std::string& prompt) {
    std::string input = readLineTrimmed(prompt);
    if (input.empty()) {
        return -1;
    }
    try {
        std::size_t pos = 0;
        int val = std::stoi(input, &pos);
        if (pos != input.size()) {
            return -1;
        }
        return val;
    } catch (...) {
        return -1;
    }
}

void printCredentialsTable(const std::vector<vault::Credential>& list) {
    std::cout << "ID    Website         Username\n";
    std::cout << "----------------------------------------\n";
    if (list.empty()) {
        std::cout << "(No saved credentials found)\n";
    } else {
        for (const auto& cred : list) {
            std::cout << std::left
                      << std::setw(6) << cred.getId()
                      << std::setw(16) << cred.getLabel().substr(0, 15)
                      << cred.getUsername() << "\n";
        }
    }
    std::cout << "----------------------------------------\n";
}

void handleViewAndReveal(vault::CredentialVault& vaultApp) {
    while (true) {
        std::cout << "\n========================================\n"
                  << "           SAVED CREDENTIALS\n"
                  << "========================================\n\n";

        const auto records = vaultApp.getAllCredentials();
        printCredentialsTable(records);

        if (records.empty()) {
            return;
        }

        std::cout << "\nSelect a credential ID to view details (or 0 to go Back): ";
        int selectedId = readMenuChoice("");
        if (selectedId == 0) {
            return;
        }

        auto credOpt = vaultApp.getCredentialById(selectedId);
        if (!credOpt.has_value()) {
            std::cout << "[!] " << vaultApp.getLastError() << "\n";
            continue;
        }

        const auto& cred = credOpt.value();
        bool revealed = false;
        while (true) {
            std::cout << "\n----------------------------------------\n"
                      << "ID       : " << cred.getId() << "\n"
                      << "Website  : " << cred.getLabel() << "\n"
                      << "Username : " << cred.getUsername() << "\n"
                      << "Password : "
                      << (revealed ? cred.getPassword() : "************") << "\n"
                      << "----------------------------------------\n\n"
                      << "[1] " << (revealed ? "Hide Password" : "Reveal Password") << "\n"
                      << "[2] Back\n\n";

            int subChoice = readMenuChoice("Enter your choice: ");
            if (subChoice == 1) {
                revealed = !revealed;
            } else if (subChoice == 2) {
                break;
            } else {
                std::cout << "[!] Invalid selection. Choose 1 or 2.\n";
            }
        }
    }
}

void handleAddCredential(vault::CredentialVault& vaultApp) {
    std::cout << "\n========================================\n"
              << "          ADD NEW CREDENTIAL\n"
              << "========================================\n\n";

    std::string label = readLineTrimmed("Enter Website / Application Name: ");
    std::string username = readLineTrimmed("Enter Username / Email: ");
    std::string password = readHiddenPassword("Enter Credential Password: ");

    if (vaultApp.addCredential(label, username, password)) {
        std::cout << "\n[+] Credential added to session! (Remember to Save Changes)\n";
    } else {
        std::cout << "\n[!] Failed to add credential: " << vaultApp.getLastError() << "\n";
    }
    wipeString(password);
}

void handleSearchCredentials(vault::CredentialVault& vaultApp) {
    std::cout << "\n========================================\n"
              << "          SEARCH CREDENTIALS\n"
              << "========================================\n\n";

    std::string query = readLineTrimmed("Enter search keyword (Website or Username): ");
    if (query.empty()) {
        std::cout << "[!] Search keyword cannot be empty.\n";
        return;
    }

    const auto matches = vaultApp.searchCredentials(query);
    std::cout << "\n";
    printCredentialsTable(matches);
}

void handleEditCredential(vault::CredentialVault& vaultApp) {
    std::cout << "\n========================================\n"
              << "            EDIT CREDENTIAL\n"
              << "========================================\n\n";

    const auto records = vaultApp.getAllCredentials();
    printCredentialsTable(records);
    if (records.empty()) {
        return;
    }

    int id = readMenuChoice("\nEnter Credential ID to edit (or 0 to cancel): ");
    if (id <= 0) {
        return;
    }

    auto existingOpt = vaultApp.getCredentialById(id);
    if (!existingOpt.has_value()) {
        std::cout << "[!] " << vaultApp.getLastError() << "\n";
        return;
    }

    const auto& current = existingOpt.value();
    std::cout << "Leave a field blank to keep its current value.\n";

    std::string newLabel = readLineTrimmed(
        "New Website [" + current.getLabel() + "]: ");
    if (newLabel.empty()) {
        newLabel = current.getLabel();
    }

    std::string newUsername = readLineTrimmed(
        "New Username [" + current.getUsername() + "]: ");
    if (newUsername.empty()) {
        newUsername = current.getUsername();
    }

    std::string newPassword = readHiddenPassword(
        "New Password (leave blank to keep current): ");
    if (newPassword.empty()) {
        newPassword = current.getPassword();
    }

    if (vaultApp.editCredential(id, newLabel, newUsername, newPassword)) {
        std::cout << "\n[+] Credential #" << id << " updated! (Remember to Save Changes)\n";
    } else {
        std::cout << "\n[!] Failed to update credential: " << vaultApp.getLastError() << "\n";
    }
    wipeString(newPassword);
}

void handleDeleteCredential(vault::CredentialVault& vaultApp) {
    std::cout << "\n========================================\n"
              << "           DELETE CREDENTIAL\n"
              << "========================================\n\n";

    const auto records = vaultApp.getAllCredentials();
    printCredentialsTable(records);
    if (records.empty()) {
        return;
    }

    int id = readMenuChoice("\nEnter Credential ID to delete (or 0 to cancel): ");
    if (id <= 0) {
        return;
    }

    auto existingOpt = vaultApp.getCredentialById(id);
    if (!existingOpt.has_value()) {
        std::cout << "[!] " << vaultApp.getLastError() << "\n";
        return;
    }

    std::string confirm = readLineTrimmed(
        "Confirm deletion of '" + existingOpt->getLabel() + "' (y/n): ");
    if (confirm == "y" || confirm == "Y") {
        if (vaultApp.deleteCredential(id)) {
            std::cout << "\n[+] Credential #" << id << " deleted from session.\n";
        } else {
            std::cout << "\n[!] " << vaultApp.getLastError() << "\n";
        }
    } else {
        std::cout << "\n[*] Deletion cancelled.\n";
    }
}

/**
 * @brief Handles locking the vault, prompting when unsaved changes exist.
 * @return true if the vault is now locked, false if the user cancelled locking.
 */
bool handleLockVault(vault::CredentialVault& vaultApp) {
    while (vaultApp.hasUnsavedChanges()) {
        std::cout << "\nYou have unsaved changes.\n\n"
                  << "[1] Save and Lock\n"
                  << "[2] Discard Changes and Lock\n"
                  << "[3] Cancel\n\n";

        int choice = readMenuChoice("Enter your choice: ");
        if (choice == 1) {
            if (vaultApp.saveChanges()) {
                std::cout << "[+] Encrypted changes saved to vault file.\n";
                vaultApp.lockVault();
                std::cout << "[+] Vault is now LOCKED.\n";
                return true;
            }
            std::cout << "[!] Save failed: " << vaultApp.getLastError()
                      << "\n    Session remains UNLOCKED so no edits are lost.\n";
            return false;
        } else if (choice == 2) {
            vaultApp.lockVault();
            std::cout << "[*] Unsaved changes discarded. Vault is now LOCKED.\n";
            return true;
        } else if (choice == 3) {
            std::cout << "[*] Lock cancelled. Returning to dashboard.\n";
            return false;
        } else {
            std::cout << "[!] Please choose 1, 2, or 3.\n";
        }
    }

    vaultApp.lockVault();
    std::cout << "\n[+] Vault is now LOCKED.\n";
    return true;
}

void runUnlockedDashboard(vault::CredentialVault& vaultApp) {
    while (vaultApp.isUnlocked() && std::cin) {
        std::cout << "\n========================================\n"
                  << "            VAULT DASHBOARD\n"
                  << "========================================\n\n"
                  << "Status: UNLOCKED"
                  << (vaultApp.hasUnsavedChanges() ? " (Unsaved Changes)" : " (All Changes Saved)")
                  << "\n"
                  << "Records: " << vaultApp.getCredentialCount() << "\n\n"
                  << "----------------------------------------\n\n"
                  << "  [1] Add New Credential\n\n"
                  << "  [2] View Saved Credentials\n\n"
                  << "  [3] Search Credentials\n\n"
                  << "  [4] Edit Credential\n\n"
                  << "  [5] Delete Credential\n\n"
                  << "  [6] Save Changes\n\n"
                  << "  [7] Lock Vault\n\n"
                  << "----------------------------------------\n\n";

        int choice = readMenuChoice("Enter your choice: ");
        switch (choice) {
            case 1:
                handleAddCredential(vaultApp);
                break;
            case 2:
                handleViewAndReveal(vaultApp);
                break;
            case 3:
                handleSearchCredentials(vaultApp);
                break;
            case 4:
                handleEditCredential(vaultApp);
                break;
            case 5:
                handleDeleteCredential(vaultApp);
                break;
            case 6:
                if (vaultApp.saveChanges()) {
                    std::cout << "\n[+] Generating fresh nonce and encrypting vault...\n"
                              << "[+] Changes saved successfully!\n";
                } else {
                    std::cout << "\n[!] Save failed: " << vaultApp.getLastError() << "\n";
                }
                break;
            case 7:
                if (handleLockVault(vaultApp)) {
                    return;
                }
                break;
            default:
                if (!std::cin) {
                    return;
                }
                std::cout << "\n[!] Invalid option. Please enter a number from 1 to 7.\n";
                break;
        }
    }
}

void handleCreateNewVault(vault::CredentialVault& vaultApp) {
    std::cout << "\n========================================\n"
              << "             CREATE VAULT\n"
              << "========================================\n\n";

    if (vaultApp.vaultExists()) {
        std::cout << "[!] A vault file already exists on disk.\n"
                  << "    To protect existing records, overwriting is disabled.\n"
                  << "    Use option [2] Unlock Existing Vault instead.\n"
                  << "----------------------------------------\n";
        return;
    }

    std::string pass1 = readHiddenPassword("Enter Master Password: ");
    std::string pass2 = readHiddenPassword("Confirm Master Password: ");

    if (pass1.empty()) {
        std::cout << "\n[!] Master password cannot be empty.\n"
                  << "----------------------------------------\n";
        wipeString(pass1);
        wipeString(pass2);
        return;
    }
    if (pass1 != pass2) {
        std::cout << "\n[!] Passwords do not match. Vault creation aborted.\n"
                  << "----------------------------------------\n";
        wipeString(pass1);
        wipeString(pass2);
        return;
    }
    wipeString(pass2);

    std::cout << "\n[+] Generating encryption key...\n"
              << "[+] Encrypting new vault...\n";

    const bool created = vaultApp.createVault(pass1);
    wipeString(pass1);

    if (created) {
        std::cout << "[+] Vault created successfully!\n\n"
                  << "----------------------------------------\n";
        runUnlockedDashboard(vaultApp);
    } else {
        std::cout << "[!] Failed to create vault: " << vaultApp.getLastError() << "\n"
                  << "----------------------------------------\n";
    }
}

void handleUnlockExistingVault(vault::CredentialVault& vaultApp) {
    std::cout << "\n========================================\n"
              << "            UNLOCK VAULT\n"
              << "========================================\n\n";

    if (!vaultApp.vaultExists()) {
        std::cout << "[!] No vault file found at the configured path.\n"
                  << "    Please choose [1] Create New Vault first.\n"
                  << "----------------------------------------\n";
        return;
    }

    std::string masterPassword = readHiddenPassword("Enter Master Password: ");
    std::cout << "\n[+] Validating vault header and deriving Argon2id key...\n";

    const bool unlocked = vaultApp.unlockVault(masterPassword);
    wipeString(masterPassword);

    if (unlocked) {
        std::cout << "[+] Authentication successful! Vault UNLOCKED.\n"
                  << "----------------------------------------\n";
        runUnlockedDashboard(vaultApp);
    } else {
        std::cout << "[!] Unlock failed: " << vaultApp.getLastError() << "\n"
                  << "----------------------------------------\n";
    }
}

} // namespace

int main(int argc, char* argv[]) {
    std::filesystem::path vaultPath = std::filesystem::path("data") / "vault.dat";
    if (argc > 1 && argv[1] != nullptr && std::string(argv[1]).size() > 0) {
        vaultPath = std::filesystem::path(argv[1]);
    }

    try {
        // Runtime polymorphism: CredentialVault owns an abstract IVaultStorage
        // base pointer backed by a concrete FileVaultStorage object.
        std::unique_ptr<vault::IVaultStorage> storage =
            std::make_unique<vault::FileVaultStorage>(vaultPath);
        vault::CredentialVault vaultApp(std::move(storage));

        while (std::cin) {
            std::cout << "\n========================================\n"
                      << "          LOCAL CREDENTIAL VAULT\n"
                      << "========================================\n\n"
                      << "         Secure Password Manager\n\n"
                      << "----------------------------------------\n\n"
                      << "  [1] Create New Vault\n\n"
                      << "  [2] Unlock Existing Vault\n\n"
                      << "  [3] Exit Application\n\n"
                      << "----------------------------------------\n\n";

            int choice = readMenuChoice("Enter your choice: ");
            if (!std::cin) {
                break;
            }

            switch (choice) {
                case 1:
                    handleCreateNewVault(vaultApp);
                    break;
                case 2:
                    handleUnlockExistingVault(vaultApp);
                    break;
                case 3:
                    vaultApp.lockVault();
                    std::cout << "\n[+] Session closed securely. Goodbye!\n";
                    return 0;
                default:
                    std::cout << "\n[!] Invalid option. Please enter 1, 2, or 3.\n";
                    break;
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "[Fatal Error] " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
