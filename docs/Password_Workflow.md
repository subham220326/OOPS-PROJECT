# Password workflow: account creation and login

## Why this differs from the credential vault

The earlier vault encrypts stored website passwords so its owner can retrieve them. AccessLab models a site's own account system: it needs to verify passwords, not retrieve the original password. It therefore stores salted password hashes rather than encrypting a list of recoverable passwords.

## Create account

1. The C++ Qt form collects a name, email, password, and confirmation. Password fields are hidden by default. The confirmation must match.
2. AuthenticationService validates name/email and password bounds and rejects an existing normalized email.
3. Through IPasswordHasher, it calls Argon2idHasher::hash. Libsodium generates a new 16-byte salt using randombytes_buf.
4. crypto_pwhash derives a 32-byte output with explicit Argon2id 1.3, opslimit 2, and memory limit 67,108,864 bytes.
5. A UserAccount holds identity metadata and a PasswordDigest. It has no plaintext-password member.
6. Through IAccountStorage, the service asks JsonAccountStorage to save the candidate collection. The database uses public JSON metadata, salt_hex, and password_hash_hex.
7. PlatformFile completes a bounded temporary write and checked commit. Only a successful save publishes the new in-memory account. A failure does not create a phantom account.
8. Input and temporary guarded password buffers are cleared. The form switches to Sign in.

The live inspector shows the actual digest returned by the hashing function, not a hardcoded demonstration string. Failed persistence labels a computed digest as not saved.

## What gets stored

The JSON record includes:

- Account ID, display name, normalized email.
- Algorithm identifier `argon2id-1.3`.
- `salt_bits: 128` and a 32-character hexadecimal salt.
- `hash_bits: 256` and a 64-character hexadecimal password hash.
- `opslimit: 2` and `memlimit_bytes: 67108864`.

A selected record is shown with its surrounding format/version envelope in the GUI. For multiple accounts this is a preview of the selected record, not a replacement for the full database file. Example_Stored_Record.json was generated from an actually executed fictional registration test.

The password itself and confirmation are not serialized. A salt is not a password or encryption key; it can be stored publicly with the verifier. Two accounts can use the same password and still obtain different salts and hashes.

## Sign in

1. Normalize and look up the email. If no account exists, perform the same Argon2id work using a random dummy record, then reject the attempt.
2. For an existing account, read its saved salt and validated supported settings.
3. Hash the submitted password using **that same stored salt**. A fresh salt must not be generated for this comparison.
4. Compare the resulting 32 bytes to the stored 32 bytes with sodium_memcmp.
5. If they match, set the active account ID and show the account page. If they differ, keep the user signed out. The public login error is generic.
6. Show the actual candidate hash next to the stored hash for this educational demonstration. Login does not rewrite the account file or save the submitted password/candidate hash.
7. Sign out clears the in-memory active account ID. A restart requires signing in again.

## Interpreting “256-bit” correctly

- 32 bytes × 8 bits = 256 bits. The GUI displays these bytes as 64 hexadecimal characters because each hexadecimal character encodes four bits.
- Salt length is independent: 16 bytes × 8 = 128 bits, displayed as 32 hexadecimal characters.
- Output length does not measure the strength of the user's chosen password. The algorithm and memory/computation costs also matter.
- This profile is frozen and validated so an account file cannot request arbitrary expensive hashing work. It is an educational baseline, not a universal recommendation for every deployed system.

## File and security boundary

JsonAccountStorage reads with a bounded std::ifstream and uses Qt Core's JSON parser. It rejects malformed structure, unexpected format/profile values, duplicate IDs/emails, and incorrectly sized/nonhex salt/hash values before any login derivation.

The account database is intentionally readable for inspection and is not AEAD-protected. Its password verifier prevents reading the original password directly; it does not stop someone who controls the database file from replacing an account's verifier. A real website protects its server and database separately. There is no server or network in this native demonstration.
