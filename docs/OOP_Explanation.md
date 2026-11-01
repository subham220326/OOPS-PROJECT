# OOP explanation and viva guide

AccessLab is a C++17 account-authentication demonstrator. The GUI, authentication coordination, password hashing, and file storage have separate responsibilities. The OOP explorer inside the application presents the same concepts interactively.

## 1. Encapsulation — UserAccount

**Definition:** keep an object's data private and offer controlled access.

Actual member declarations and getters from UserAccount.h:

```cpp
class UserAccount {
    std::uint32_t id_;
    std::string displayName_, email_;
    PasswordDigest digest_;
public:
    const std::string& email() const { return email_; }
    const PasswordDigest& digest() const { return digest_; }
```

The constructor validates identity data. The account deliberately has no plaintext-password member. Const getters prevent callers from directly changing its fields through those references.

**Viva answer:** “I encapsulated account information in UserAccount. The password is only an input to hashing, and the resulting digest is stored with the account. Other classes use getters rather than accessing private members.”

## 2. Abstraction — IPasswordHasher and IAccountStorage

**Definition:** describe the operations a caller needs while hiding implementation details.

Actual password-hashing interface:

```cpp
class IPasswordHasher {
public:
    virtual ~IPasswordHasher() = default;
    virtual PasswordDigest hash(const SecretBuffer& password) const = 0;
    virtual VerificationResult verify(const SecretBuffer& password,
                                     const PasswordDigest& stored) const = 0;
};
```

The storage interface similarly declares `load()` and `save()`. Pure virtual functions make both interfaces abstract; they cannot be instantiated directly.

**Viva answer:** “The authentication service needs hashing and storage operations but does not need low-level cryptographic or file code. Abstract interfaces provide those contracts.”

## 3. Inheritance — Argon2idHasher and JsonAccountStorage

**Definition:** derive a class from an existing base class.

Actual declarations:

```cpp
class Argon2idHasher : public IPasswordHasher {
```

```cpp
class JsonAccountStorage : public IAccountStorage {
```

The derived classes implement the required functions with `override`. The GUI also inherits QMainWindow to use Qt's window behavior.

**Viva answer:** “Argon2idHasher is a concrete implementation of IPasswordHasher. JsonAccountStorage is a concrete implementation of IAccountStorage. Public inheritance permits using each through its abstract base.”

## 4. Runtime polymorphism — AuthenticationService

**Definition:** a call through a base-class interface runs the appropriate concrete implementation at runtime.

Actual owned collaborators:

```cpp
std::unique_ptr<IPasswordHasher> hasher_;
std::unique_ptr<IAccountStorage> storage_;
```

Actual calls during registration:

```cpp
const auto digest = hasher_->hash(password);
storage_->save(next);
```

At runtime these call Argon2idHasher and JsonAccountStorage. Automated tests provide a CountingHasher that delegates to real Argon2id, and a storage implementation that deliberately fails. This checks that the service works through its interfaces.

**Viva answer:** “The pointer's type is the abstract base, while the object has a derived type. Virtual dispatch selects the derived implementation. The tests demonstrate a different storage implementation without changing the service.”

The base destructors are virtual so deleting a derived object through a base pointer performs the correct cleanup.

## 5. Composition and unique ownership

**Definition:** an object owns other objects: a ‘has-a’ relationship.

AuthenticationService owns:

```cpp
std::vector<UserAccount> accounts_;
std::unique_ptr<IPasswordHasher> hasher_;
std::unique_ptr<IAccountStorage> storage_;
```

AuthenticationWindow owns:

```cpp
std::unique_ptr<AuthenticationService> service_;
```

**Viva answer:** “A service has accounts, a hasher, and storage. The GUI has the service. unique_ptr expresses one owner and automatically deletes the owned object. Qt parent widgets own their child widgets.”

## 6. Constructors

**Definition:** initialize a new object and establish valid starting state.

Actual UserAccount constructor:

```cpp
UserAccount::UserAccount(std::uint32_t id, std::string name,
                         std::string email, PasswordDigest digest)
    : id_(id), displayName_(std::move(name)),
      email_(normalizeEmail(email)), digest_(std::move(digest)) {
    if (id == 0 || id > 1000000)
        throw std::runtime_error("Account ID is outside the supported range.");
    validateName(displayName_);
}
```

AuthenticationService's constructor takes ownership of hashing/storage objects, checks them, loads accounts, and prepares a dummy verifier for unknown-email attempts.

SecretBuffer also demonstrates constructor overloading: `SecretBuffer(std::size_t)` allocates a specified byte count, while `SecretBuffer(std::string_view)` initializes a buffer from text. This is distinct from virtual runtime polymorphism.

**Viva answer:** “Constructors normalize and validate fields before an account is usable. The service starts with no signed-in user and loads existing records through the storage interface.”

## 7. Destructors and RAII — SecretBuffer

**Definition:** a destructor runs at the end of an object's lifetime. RAII attaches cleanup to ownership so normal returns and exceptions both clean up.

Actual cleanup:

```cpp
SecretBuffer::~SecretBuffer() { clear(); }

void SecretBuffer::clear() noexcept {
    sodium_free(bytes_);
    bytes_ = nullptr;
    size_ = 0;
}
```

Actual copy prevention:

```cpp
SecretBuffer(const SecretBuffer&) = delete;
SecretBuffer& operator=(const SecretBuffer&) = delete;
```

SecretBuffer allocates guarded memory with sodium_malloc. Its move constructor transfers ownership, while its destructor wipes/releases the allocation through sodium_free. Temporary-file and OS-lock helpers also use resource ownership.

**Viva answer:** “A sensitive buffer has one owner. It cannot be accidentally copied, and its destructor handles cleanup even when hashing or storage throws. This helps memory hygiene but does not guarantee that Qt or the OS retained no other copies.”

## 8. STL containers

**Definition:** standard library containers manage collections and fixed-size data.

- `vector<UserAccount>` stores the account collection.
- `array<unsigned char, 16>` and `array<unsigned char, 32>` store fixed-size salts/hashes.
- `set` checks duplicate account IDs/emails during file parsing and serialization.
- `string` stores identity text and hexadecimal output.

The program uses ordinary loops and functions. It does not introduce a complex framework, custom cryptography, or concurrency.

## 9. File handling and exceptions

**Definition:** file handling persists state; exceptions signal a failure without continuing as though the operation succeeded.

Actual bounded file input:

```cpp
std::ifstream stream(path_, std::ios::binary | std::ios::ate);
if (!stream) throw std::runtime_error("Cannot open account storage.");
const auto size = stream.tellg();
if (size <= 0 || size > static_cast<std::streamoff>(MaxFileBytes))
    throw std::runtime_error("Account file has an invalid size.");
```

Actual registration commit sequence:

```cpp
auto next = accounts_;
next.emplace_back(largest + 1, name, trace_.email, digest);
storage_->save(next);
accounts_.swap(next);
```

Only a successful file commit publishes the new account in memory. The GUI catches `std::exception`, clears password fields, displays an error, and keeps the form enabled.

**Viva answer:** “The file contains identities, salts and password hashes. The service saves a proposed collection before updating the live collection. File exceptions stop registration, so a failed save cannot produce a phantom account.”

## What Qt and libsodium do

Qt supplies native C++ widgets and JSON parsing. Libsodium supplies Argon2id, cryptographic randomness, constant-time comparison, and guarded memory. Our C++ classes implement validation, account/session state, workflow coordination, serialization, and checked persistence.

**One-minute project explanation:** “My software demonstrates website-style registration and login in a native C++ interface. During registration it creates a random salt, computes a 256-bit Argon2id hash, and stores only the verifier and identity metadata. During login it reuses the stored salt, hashes the submitted password, and compares the results. The GUI shows the real values. Private account fields demonstrate encapsulation, two interfaces demonstrate abstraction, their implementations demonstrate inheritance, and virtual calls demonstrate runtime polymorphism. Composition, unique_ptr, RAII, STL, and exceptions complete the OOP design.”
