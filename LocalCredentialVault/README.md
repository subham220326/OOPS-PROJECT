# Local Credential Vault — C++17 OOP Mini-Project

**Project Title:** Local Credential Vault — Password-Based Access and Authenticated Local Storage  
**Language & Standard:** C++17  
**Cryptography Library:** `libsodium` (Argon2id + XChaCha20-Poly1305 IETF)  

A self-contained, menu-driven C++17 console application that protects website and application credentials behind a master password using real authenticated encryption and clean Object-Oriented Programming (OOP) architecture.

---

## 1. Key Features

- **Password-Derived Encryption Key:** Uses `libsodium`'s `crypto_pwhash` (**Argon2id**) with a 16-byte random salt to derive a 256-bit encryption key from the master password. The master password is never stored on disk.
- **Authenticated Encryption (AEAD):** Protects serialized records using **XChaCha20-Poly1305** (`crypto_aead_xchacha20poly1305_ietf_*`) with a fresh 24-byte random nonce on every save and the 56-byte file header bound as Associated Data (AAD).
- **Complete Credential Lifecycle:** Create vault, unlock vault, add credentials, view saved credentials (with passwords masked by default and revealed only on request), search by website/username, edit records, and delete records with confirmation.
- **Safe Local Persistence:** Validates file headers and size limits before running expensive key derivation, blocks overwriting an existing vault during creation, and writes updates via a temporary file (`vault.dat.tmp`) followed by checked replacement.
- **Session & Dirty-State Protection:** Enforces `LOCKED` vs. `UNLOCKED` states, prompts to Save, Discard, or Cancel when locking with unsaved edits, and zeroes sensitive memory via `SecretBuffer` (`sodium_memzero`).

---

## 2. Project Structure

```text
LocalCredentialVault/
|-- CMakeLists.txt
|-- Makefile
|-- README.md
|-- .gitignore
|-- include/
|   |-- Credential.h
|   |-- CredentialVault.h
|   |-- CryptoService.h
|   |-- SecretBuffer.h
|   |-- IVaultStorage.h
|   |-- FileVaultStorage.h
|-- src/
|   |-- main.cpp
|   |-- Credential.cpp
|   |-- CredentialVault.cpp
|   |-- CryptoService.cpp
|   |-- SecretBuffer.cpp
|   |-- FileVaultStorage.cpp
|-- data/
|   |-- sample_vault.dat
|-- tests/
|   |-- test_vault.cpp
|-- docs/
    |-- OOP_Explanation.md
    |-- Project_Workflow.md
    |-- File_Format.md
```

---

## 3. Installing Prerequisites (`libsodium`, CMake, C++17 Compiler)

### Windows (Primary College Lab Environment)

#### Option A: MSYS2 MinGW-w64 (Recommended for VS Code on Windows)
1. Install [MSYS2](https://www.msys2.org/) and open the **MSYS2 UCRT64** (or **MinGW64**) terminal.
2. Install the C++17 toolchain, CMake, and `libsodium`:
   ```bash
   pacman -Syu
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-libsodium
   ```
3. Add `C:\msys64\ucrt64\bin` to your Windows `PATH`.

#### Option B: Visual Studio / MSVC + vcpkg
1. Install Visual Studio (with "Desktop development with C++") and [vcpkg](https://github.com/microsoft/vcpkg).
2. Install `libsodium`:
   ```powershell
   vcpkg install libsodium:x64-windows
   ```
3. Configure CMake with the vcpkg toolchain file:
   ```powershell
   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build --config Release
   ```

### Linux (Debian / Ubuntu)
```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libsodium-dev
```

### macOS (Homebrew)
```bash
brew install cmake pkg-config libsodium
```

---

## 4. Building and Running the Project

### Using CMake (Windows, Linux, macOS)
```bash
cmake -B build -S .
cmake --build build
```

Run the automated verification suite (12 tests):
```bash
./build/test_vault        # Linux / macOS / MSYS2
.\build\Release\test_vault.exe  # Windows MSVC
```

Run the interactive credential vault application:
```bash
./build/vault_app         # Uses default path: data/vault.dat
./build/vault_app data/sample_vault.dat
```

### Using Make (Fallback if CMake is unavailable)
```bash
make
make test
./build/vault_app
```

### Running in Visual Studio Code (VS Code)
1. Install the **C/C++** (`ms-vscode.cpptools`) and **CMake Tools** (`ms-vscode.cmake-tools`) extensions in VS Code.
2. Open the `LocalCredentialVault` folder (`File -> Open Folder...`).
3. When prompted by CMake Tools, select your compiler kit (e.g., `GCC (ucrt64)` on Windows or `GCC` on Linux).
4. Click **Build** in the bottom status bar to compile `vault_app` and `test_vault`.
5. Open the integrated terminal (`Ctrl + ~`) and run `./build/vault_app` so interactive password prompts work inside a real terminal.

---

## 5. Pre-Populated Demo Vault (`data/sample_vault.dat`)

For practical examination demonstrations, a sample encrypted vault is included at `data/sample_vault.dat`:
- **Master Password:** `Subham@OOP2026`
- **Stored Fictional Records:**
  1. `Google` (`example@gmail.com`)
  2. `GitHub` (`developer123`)
  3. `Instagram` (`user_example`)

To open the sample vault directly:
```bash
./build/vault_app data/sample_vault.dat
```

---

## 6. Security Boundary & Honest Limitations

This project is an educational C++17 OOP prototype with genuine authenticated encryption, subject to the following explicit scope boundaries:
1. **Offline Master-Password Guessing:** A copied `vault.dat` file cannot be read without the master password, and Argon2id (`64 MiB` memory cost) slows brute-force attacks, but a weak master password can still be guessed offline.
2. **No Master-Password Recovery:** Because the master password is never stored and no backdoor key exists, forgetting the master password makes the encrypted records permanently unrecoverable.
3. **Compromised Host / Unlocked Session:** While `SecretBuffer` and `Credential` overwrite sensitive memory with `sodium_memzero()` on lock/destruction, a prototype user-space console app cannot defend against privileged OS malware, keyloggers, or screen capture while a session is unlocked.
4. **Rollback / External File Deletion:** Tampering with `vault.dat` is detected by the Poly1305 tag, and failed writes leave the prior file intact, but an attacker with write access to the folder could delete `vault.dat` or replace it with an older valid snapshot of the same vault.
