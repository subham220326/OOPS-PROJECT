# Verification report

Executed on **24 October 2026**, on macOS 27.0 / Apple Silicon (arm64). Toolchain: AppleClang 21.0.0, CMake 4.4.4, Qt 6.10.0, libsodium 1.0.22, C++17.

The Release build compiled auth_core, auth_gui, accesslab, test_auth, and test_auth_gui with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow` and no compiler warnings.

**28 verification scenarios passed, 0 failed: 17 core C++ and 11 C++ GUI scenarios**, inside the two CTest entries authentication_core and authentication_gui. All accounts/passwords used in verification are fictional and stored in temporary test folders.

## Executed core scenarios

- **PASS** — Real Argon2id produces 128-bit salt, 256-bit hash, and correct verification
- **PASS** — Same password with fresh salts yields different stored hashes
- **PASS** — Register, normalize email, sign in, access session, and sign out
- **PASS** — Wrong password and unknown account never create a session
- **PASS** — Duplicate email is rejected without writing or replacing an account
- **PASS** — Password boundaries, including 12-byte and 1024-byte round trips
- **PASS** — Name and email validation rejects malformed and oversized values
- **PASS** — Persistence stores real verifiers and no entered password
- **PASS** — Runtime polymorphism uses both abstract interfaces and equal-cost unknown-account verification
- **PASS** — Failed commit leaves saved and in-memory accounts unchanged
- **PASS** — Active session guards prevent switching identity without signing out
- **PASS** — Malformed JSON, bad profile, invalid hex, and duplicate stored IDs/emails are rejected
- **PASS** — Bounded file sizes and cooperative file locking
- **PASS** — 500-account limit and duplicate-serialization protection
- **PASS** — SecretBuffer transfers ownership and forbids accidental copying
- **PASS** — Real write failure preserves database and registration state; POSIX private permissions
- **PASS** — Symlink database targets are refused

## Executed GUI scenarios

- **PASS** — Website-style registration form is real and password input is hidden
- **PASS** — Mismatched confirmation and invalid email cannot create an account
- **PASS** — Create account persists real 128-bit salt and 256-bit hash and clears input
- **PASS** — Second account with the same password has a different salt and hash
- **PASS** — Duplicate account rejected without replacing saved records
- **PASS** — Wrong-password login shows a real failed hash comparison and no session
- **PASS** — Correct login shows matching hashes and a genuine account session
- **PASS** — Account records show actual saved JSON with hashes and no plaintext password
- **PASS** — OOP explorer explains all eight concepts using real project classes
- **PASS** — Accounts survive application-window restart; correct password still authenticates
- **PASS** — Failed database write creates no account and leaves the GUI usable

## What the checks establish

The tests use real libsodium Argon2id, random salts, and constant-time comparison. They verify persisted salt/hash values and scan saved records for the fictional entered password. The polymorphism test substitutes a CountingHasher that still delegates to actual Argon2id; it does not simulate cryptographic results. File-failure testing includes both an injected commit failure and a genuinely unwritable POSIX directory.

GUI tests are C++ Qt Test code that clicks the real widgets, fills the forms, checks the hash values and session state, navigates records/OOP pages, and reopens a new application window on the saved database. They run with Qt's offscreen platform. Screenshots are direct widget captures from the compiled application, not drawn mockups, and were visually inspected. Example_Stored_Record.json was exported from an actually executed fictional registration.

Different salts/hashes in two observations are not a proof of randomness. Absence of a searched password string from a file is a useful smoke check, not a formal security proof. The account database contains public identity/verifier metadata and is not encrypted or authenticated as a whole; no tamper-proof database claim is made.

## Reproduce

From the configured project folder:

```sh
cmake --build build --parallel
ctest --test-dir build -V
QT_QPA_PLATFORM=offscreen ./build/test_auth_gui ./screenshots
```

On Windows with the Visual Studio generator:

```powershell
cmake --build build --config Release --parallel
ctest --test-dir build -C Release -V
.\build\Release\test_auth.exe
.\build\Release\test_auth_gui.exe
```

## Platform and scope limits

Native interactive Cocoa operation and execution on Windows/Linux were not independently verified. Two POSIX-specific core scenarios and one POSIX-specific GUI write-failure scenario are conditionally excluded on Windows; those builds contain 15 core and 10 GUI scenarios. No Windows pass result is claimed.

No real website, HTTPS server, persistent web-session token, recovery flow, rate limiter, or production security review is included. The app demonstrates account password hashing and OOP locally. The read-only account inspector is intentionally available for teaching with fictional data.

## Packaged macOS application

The Apple Silicon app bundle includes the Qt and libsodium dynamic runtime libraries. Its local ad-hoc signature passed `codesign --verify --deep --strict`. An offscreen startup smoke check passed with an explicit temporary account-file path and no external Qt/Homebrew runtime paths; startup did not create an account database. Eleven bundled Mach-O dependency lists were checked. The supplied build targets macOS 27.0 and is not Apple-notarized.
