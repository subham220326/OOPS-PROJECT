# Binary Vault File Format Specification (`vault.dat`)

`LocalCredentialVault` stores all data in a compact, self-describing binary file (`data/vault.dat`). Passwords and credential records are never written in plaintext.

---

## 1. Overall File Layout

```
+-----------------------------------------------------------------------+
| Public Header (56 bytes, unencrypted, authenticated via AEAD AAD)     |
+-----------------------------------------------------------------------+
| Encrypted Payload (N bytes, XChaCha20 stream cipher output)           |
+-----------------------------------------------------------------------+
| Authentication Tag (16 bytes, Poly1305 MAC over Header + Payload)     |
+-----------------------------------------------------------------------+
```

- **Minimum Valid File Size:** `56 (Header) + 4 (Encrypted 0-record count) + 16 (Poly1305 Tag) = 76 bytes`
- **Maximum Permitted File Size:** `1,048,576 bytes (1 MiB)`

---

## 2. Public Header Structure (56 Bytes — Bound as Associated Data)

All multi-byte integers are stored in **little-endian** byte order.

| Byte Offset | Size (Bytes) | Field Name | Expected Value | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `0..3` | 4 | `magic` | `"LCV1"` (`0x4C 0x43 0x56 0x31`) | Identifies file as a Local Credential Vault file |
| `4` | 1 | `version` | `1` (`uint8_t`) | Binary format version number |
| `5` | 1 | `kdf_alg` | `2` (`crypto_pwhash_ALG_ARGON2ID13`) | Key derivation algorithm identifier (Argon2id v1.3) |
| `6..7` | 2 | `reserved` | `0x0000` (`uint16_t`) | Reserved alignment bytes (must be zero) |
| `8..11` | 4 | `opslimit` | `2` (`uint32_t` LE) | Argon2id interactive operations cost parameter |
| `12..15` | 4 | `memlimit` | `67108864` (`uint32_t` LE, 64 MiB) | Argon2id interactive memory cost parameter in bytes |
| `16..31` | 16 | `salt` | Random (`crypto_pwhash_SALTBYTES`) | Per-vault random salt generated at vault creation |
| `32..55` | 24 | `nonce` | Random (`crypto_aead_xchacha20poly1305_ietf_NPUBBYTES`) | Fresh random nonce regenerated on every save |

**Why the header is bound as Associated Data (AAD):**  
The entire 56-byte header is passed as `ad` (`associatedData`) to `crypto_aead_xchacha20poly1305_ietf_encrypt()` and `decrypt()`. If an attacker modifies any header byte (such as the version or KDF cost fields), Poly1305 authentication fails immediately during unlock.

---

## 3. Decrypted Plaintext Payload Layout

After `crypto_aead_xchacha20poly1305_ietf_decrypt()` verifies the 16-byte authentication tag, the decrypted `SecretBuffer` has the following binary structure:

| Field | Type | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| `record_count` | `uint32_t` (LE) | 4 | Number of serialized credential records (`0 .. 1000`) |
| `records[]` | Variable | Variable | Sequence of `record_count` packed records (see below) |

### Individual Record Format

| Field | Type | Size (Bytes) | Constraints |
| :--- | :--- | :--- | :--- |
| `id` | `uint32_t` (LE) | 4 | Positive unique integer identifier (`>= 1`) |
| `label_len` | `uint16_t` (LE) | 2 | Length of `label` in bytes (`1 .. 128`) |
| `label` | UTF-8 / ASCII bytes | `label_len` | Website or application name (unique, case-insensitive) |
| `username_len` | `uint16_t` (LE) | 2 | Length of `username` in bytes (`1 .. 128`) |
| `username` | UTF-8 / ASCII bytes | `username_len` | Account username or email |
| `password_len` | `uint16_t` (LE) | 2 | Length of `password` in bytes (`1 .. 256`) |
| `password` | UTF-8 / ASCII bytes | `password_len` | Account password |

If trailing bytes remain after reading `record_count` records, or if any length prefix exceeds the remaining buffer or field bounds, deserialization rejects the payload and leaves the vault `LOCKED`.
