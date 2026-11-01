# Five-minute college demonstration

Use fictional accounts and an isolated `data/exam-accounts.json` file. Build/run instructions are in README.

1. **Create an account.** Use the name Fictional Student and email `student@example.test`, with a fictional passphrase of at least 12 bytes. Enter matching confirmation. Explain that the C++ form delegates to AuthenticationService.
2. **Explain the generated values.** Point to the 128-bit salt, 256-bit Argon2id hash, and completed registration steps. The password field has been cleared; no password is saved directly.
3. **Show actual storage.** Open Account records, select the row, and point out the JSON's email, algorithm, salt_hex, password_hash_hex, and cost settings. The name/email are public metadata. The password is absent.
4. **Try a wrong password.** Return to Authenticate and sign in with the account email and a wrong fictional password. The candidate hash differs from the stored hash and no session is created.
5. **Sign in correctly.** Use the correct password. The stored and recomputed hashes match; the signed-in account page appears. Sign out.
6. **Demonstrate salt.** Create a second fictional account with a different email and the same password. The salt and hash differ. Explain why a salt is created during registration but reused during login.
7. **Demonstrate OOP.** Open OOP explorer. Show private fields, the abstract hasher/storage interfaces, derived classes, and the calls through base pointers. Point out composition, unique_ptr, RAII, and exception handling.
8. **Restart.** Close and reopen with the same database path. Sign in to show real persistence. Run CTest to show the automated evidence.

## Short viva answers

**Why not AES-256 for account login?** A site only needs to check the entered password. A salted password hash supports verification without keeping a recoverable original. Encryption is appropriate for a vault that must retrieve stored secrets, which is a different job.

**What is 256-bit here?** The hash output is 32 bytes. The salt is a separate 16-byte random value. This does not mean a weak password has 256 bits of entropy.

**Why Argon2id?** It is a memory-hard password-hashing algorithm provided by libsodium. The project never implements cryptographic algorithms manually.

**Why must a login use the stored salt?** A different salt would produce a different result even for the same password, so the hash comparison would fail.

**Where is polymorphism?** AuthenticationService owns unique_ptr<IPasswordHasher> and unique_ptr<IAccountStorage>. Virtual calls run Argon2idHasher and JsonAccountStorage. Tests replace storage with a failing implementation to verify error handling.

**Where is encapsulation?** UserAccount keeps its identity/digest fields private, exposes const getters, validates construction, and has no plaintext-password member.

**What happens if saving fails?** A candidate collection is saved first. The service swaps it into memory only after the commit succeeds. The existing database and original accounts remain usable on pre-commit failure.

**Is this a deployed website?** No. It is a native C++ educational application with website-style forms. A real website would use server-side account storage, HTTPS, secure web sessions, and additional controls.
