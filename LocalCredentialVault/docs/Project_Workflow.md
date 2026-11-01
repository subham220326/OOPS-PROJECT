# Project Workflow & Session Lifecycle

This document traces how `LocalCredentialVault` executes vault creation, unlocking, credential management, authenticated encryption, and checked persistence.

---

## 1. End-to-End Application Flow

```
Launch Application (src/main.cpp)
       |
       +--> Initialize libsodium (CryptoService::initialize -> sodium_init)
       |
       +--> Display Main Menu
             |-- [1] Create New Vault
             |-- [2] Unlock Existing Vault
             |-- [3] Exit Application
```

---

## 2. Creating a New Vault

1. **Pre-check (`FileVaultStorage::exists`)**: Verify that `data/vault.dat` does not already exist so an existing vault is never overwritten.
2. **Master Password Input (`readHiddenPassword`)**: Read and confirm the master password with terminal echo disabled.
3. **Random Salt Generation (`CryptoService::generateSalt`)**: Generate a fresh 16-byte salt using `randombytes_buf()`.
4. **Key Derivation (`CryptoService::deriveKey`)**: Derive a 32-byte key in a `SecretBuffer` using `crypto_pwhash()` with `crypto_pwhash_ALG_ARGON2ID13` (`opslimit = 2`, `memlimit = 64 MiB`).
5. **Initial Encryption (`CredentialVault::buildEncryptedVaultBytes`)**:
   - Serialize an empty credential list (`record_count = 0`, 4 bytes) into a `SecretBuffer`.
   - Generate a fresh 24-byte random nonce (`randombytes_buf`).
   - Build the 56-byte public header (`LCV1`, version `1`, algorithm `2`, KDF parameters, 16-byte salt, 24-byte nonce).
   - Encrypt the 4-byte plaintext with `crypto_aead_xchacha20poly1305_ietf_encrypt`, passing the 56-byte header as **Associated Data (AAD)** to produce 20 bytes of ciphertext + tag.
6. **Checked Commit (`FileVaultStorage::createNew`)**: Write the 76-byte file to `data/vault.dat.tmp`, verify the write, and rename to `data/vault.dat`.
7. **Enter Unlocked Session**: Wipe the master password string from memory while keeping the 32-byte derived key inside `masterKey_` (`SecretBuffer`).

---

## 3. Unlocking an Existing Vault

1. **Bounded File Read (`FileVaultStorage::load`)**: Confirm `data/vault.dat` exists and its size is between 76 bytes and 1 MiB, then read its bytes.
2. **Header Validation Before Expensive Work**:
   - Verify magic bytes == `"LCV1"` and format version == `1`.
   - Verify `kdf_alg == 2` (Argon2id) and that `opslimit` (2) and `memlimit` (64 MiB) match the supported interactive profile before executing Argon2id.
3. **Key Derivation (`CryptoService::deriveKey`)**: Extract the 16-byte salt from header bytes `[16..32)` and derive the 32-byte candidate key from the entered master password.
4. **Authenticated Decryption (`CryptoService::decrypt`)**:
   - Call `crypto_aead_xchacha20poly1305_ietf_decrypt` with the 56-byte header as AAD and the 24-byte nonce from header bytes `[32..56)`.
   - If the master password is wrong or **any single bit** of the header, nonce, ciphertext, or tag was altered, verification fails immediately (`rc != 0`), `decryptedPlaintext` is wiped, and the vault stays `LOCKED`.
5. **Record Deserialization (`CredentialVault::deserializeCredentials`)**: Parse the decrypted bytes into `std::vector<Credential>`, validating record counts, field lengths, and unique IDs/labels.
6. **Transition to `UNLOCKED`**: Store the active key and credentials in memory and open the Vault Dashboard.

---

## 4. In-Memory Credential Management & Dirty-State Tracking

Every operation in `CredentialVault` first calls `ensureUnlocked()`:
- **Add Credential (`addCredential`)**: Validates non-empty bounds (`<= 128` chars for label/username, `<= 256` chars for password), checks for duplicate labels, appends a new `Credential`, and sets `hasUnsavedChanges_ = true`.
- **View & Reveal (`getAllCredentials`, `getCredentialById`)**: Displays all records in a formatted table with passwords masked as `************` until the user explicitly chooses `[1] Reveal Password` on a selected record.
- **Search (`searchCredentials`)**: Performs a case-insensitive substring match across labels and usernames.
- **Edit (`editCredential`)**: Updates the selected record's fields after validation and sets `hasUnsavedChanges_ = true`.
- **Delete (`deleteCredential`)**: Removes the selected record after user confirmation and sets `hasUnsavedChanges_ = true`.

---

## 5. Saving Changes & Atomic Replacement

When the user selects `[6] Save Changes` (or `[1] Save and Lock`):
1. `serializeCredentials()` packs all current `Credential` objects into a `SecretBuffer`.
2. `crypto_.generateNonce()` draws a **brand-new 24-byte random nonce** via `randombytes_buf()`.
3. `crypto_.encrypt()` encrypts the serialized buffer under the active `masterKey_` with the updated 56-byte header bound as AAD.
4. `FileVaultStorage::save()` writes the encrypted bytes to `data/vault.dat.tmp`, flushes and closes the file, verifies the written file size, and renames `data/vault.dat.tmp` over `data/vault.dat`.
5. If writing or renaming fails, the previous `data/vault.dat` remains untouched on disk and `hasUnsavedChanges_` remains `true` so the user does not lose their in-memory edits.

---

## 6. Locking the Vault & Cleaning Sensitive Memory

When the user chooses `[7] Lock Vault`:
1. If `hasUnsavedChanges_` is `true`, the application prompts:
   - `[1] Save and Lock`
   - `[2] Discard Changes and Lock`
   - `[3] Cancel`
2. Once locking proceeds, `CredentialVault::lockVault()`:
   - Destroys all `Credential` objects in `credentials_` (each `~Credential()` calls `sodium_memzero` on its password buffer).
   - Calls `masterKey_.clear()` (which runs `sodium_memzero` on the 32-byte encryption key).
   - Zeroes the stored salt vector and resets `isUnlocked_ = false` and `hasUnsavedChanges_ = false`.
