# Object-Oriented Programming (OOP) Concepts Explanation

**Project Title:** Local Credential Vault — Password-Based Access and Authenticated Local Storage  
**Prepared for:** Undergraduate OOP Practical Examination & Viva  

This guide explains how the nine core Object-Oriented Programming and C++17 concepts are implemented in the `LocalCredentialVault` project, including exact class locations, code snippets from the codebase, and concise viva explanations.

---

## 1. Encapsulation

### Simple Definition
Encapsulation is the bundling of data members and the methods that operate on them into a single class while restricting direct external access to the internal data using `private` access specifiers.

### Where It Is Implemented
- `Credential` (`include/Credential.h`, `src/Credential.cpp`)
- `CredentialVault` (`include/CredentialVault.h`, `src/CredentialVault.cpp`)

### Code Snippet from Implementation
```cpp
class Credential {
public:
    int getId() const;
    const std::string& getLabel() const;
    const std::string& getUsername() const;
    const std::string& getPassword() const;

    void setLabel(const std::string& label);
    void setUsername(const std::string& username);
    void setPassword(const std::string& password);

private:
    int id_;
    std::string label_;
    std::string username_;
    std::string password_;
};
```

### Viva Explanation
In `Credential`, the sensitive fields (`id_`, `label_`, `username_`, and `password_`) are declared `private` so external functions like `main()` cannot modify them directly or set invalid empty/oversized strings. Every modification goes through public setter methods (`setLabel`, `setUsername`, `setPassword`) that enforce length bounds (128 bytes for labels/usernames, 256 bytes for passwords) and wipe old password memory before writing a new value.

---

## 2. Abstraction

### Simple Definition
Abstraction means exposing only the essential operations an object performs while hiding the low-level implementation details behind a clean interface.

### Where It Is Implemented
- `IVaultStorage` (`include/IVaultStorage.h`)
- `CryptoService` (`include/CryptoService.h`)

### Code Snippet from Implementation
```cpp
class IVaultStorage {
public:
    virtual ~IVaultStorage() = default;

    virtual bool exists() const = 0;
    virtual bool createNew(const std::vector<unsigned char>& data) = 0;
    virtual bool load(std::vector<unsigned char>& data) = 0;
    virtual bool save(const std::vector<unsigned char>& data) = 0;
    virtual std::string getLastError() const = 0;
};
```

### Viva Explanation
`IVaultStorage` is an abstract class containing pure virtual functions (`= 0`). It defines *what* storage operations the vault needs (`exists`, `createNew`, `load`, `save`) without exposing *how* bytes are written to disk. Similarly, `CryptoService` hides low-level `libsodium` C pointers and byte lengths behind high-level methods like `deriveKey()`, `encrypt()`, and `decrypt()`.

---

## 3. Inheritance

### Simple Definition
Inheritance is the mechanism by which a derived class acquires the interface and properties of a base class, establishing an **"is-a"** relationship.

### Where It Is Implemented
- `FileVaultStorage` (`include/FileVaultStorage.h`, `src/FileVaultStorage.cpp`) publicly inheriting from `IVaultStorage` (`include/IVaultStorage.h`).

### Code Snippet from Implementation
```cpp
class FileVaultStorage : public IVaultStorage {
public:
    explicit FileVaultStorage(std::filesystem::path filePath);
    ~FileVaultStorage() override = default;

    bool exists() const override;
    bool createNew(const std::vector<unsigned char>& data) override;
    bool load(std::vector<unsigned char>& data) override;
    bool save(const std::vector<unsigned char>& data) override;
    std::string getLastError() const override;
```

### Viva Explanation
`FileVaultStorage` uses public inheritance (`: public IVaultStorage`) to implement local binary file persistence. Because of inheritance, `FileVaultStorage` *is-a* `IVaultStorage`, and our automated test suite can also create a `FailingSaveDecorator : public IVaultStorage` to test disk write failures without modifying a single line of `CredentialVault`.

---

## 4. Runtime Polymorphism

### Simple Definition
Runtime polymorphism occurs when a call to a `virtual` member function through a base-class pointer or reference is resolved at runtime to the overridden function in the concrete derived class.

### Where It Is Implemented
- `CredentialVault` (`include/CredentialVault.h`, `src/CredentialVault.cpp`) calling virtual methods through `std::unique_ptr<IVaultStorage> storage_`.

### Code Snippet from Implementation
```cpp
// In src/main.cpp:
std::unique_ptr<vault::IVaultStorage> storage =
    std::make_unique<vault::FileVaultStorage>(vaultPath);
vault::CredentialVault vaultApp(std::move(storage));

// In src/CredentialVault.cpp:
if (!storage_->load(fileBytes)) {
    lastError_ = storage_->getLastError();
    return false;
}
```

### Viva Explanation
`CredentialVault` holds a `std::unique_ptr<IVaultStorage>` rather than a concrete `FileVaultStorage` object. When `storage_->load(fileBytes)` or `storage_->save(encryptedBytes)` is called, C++ uses the virtual table (`vtable`) at runtime to dispatch the call to `FileVaultStorage::load()` or `FileVaultStorage::save()`.

---

## 5. Constructors

### Simple Definition
A constructor is a special member function invoked automatically when an object is created to initialize its data members and establish class invariants.

### Where It Is Implemented
- Default and parameterized constructors in `Credential` (`src/Credential.cpp`)
- Explicit constructors in `SecretBuffer`, `FileVaultStorage`, and `CredentialVault`

### Code Snippet from Implementation
```cpp
Credential::Credential(int id,
                       const std::string& label,
                       const std::string& username,
                       const std::string& password)
    : id_(0), label_(), username_(), password_() {
    setId(id);
    validateFields(label, username, password);
    label_ = label;
    username_ = username;
    password_ = password;
}
```

### Viva Explanation
Constructors guarantee that no object starts in an uninitialized or invalid state. `Credential` uses member initializer lists and validates field sizes immediately upon construction, while `CredentialVault`'s constructor checks that the `IVaultStorage` pointer is non-null and initializes `libsodium`.

---

## 6. Destructors & RAII

### Simple Definition
A destructor (`~ClassName()`) is a special member function executed automatically when an object goes out of scope or is deleted. Paired with **RAII (Resource Acquisition Is Initialization)**, it ensures deterministic cleanup of sensitive resources.

### Where It Is Implemented
- `SecretBuffer::~SecretBuffer()` (`src/SecretBuffer.cpp`)
- `Credential::~Credential()` (`src/Credential.cpp`)
- `CredentialVault::~CredentialVault()` (`src/CredentialVault.cpp`)
- `IVaultStorage::~IVaultStorage()` (virtual destructor in `include/IVaultStorage.h`)

### Code Snippet from Implementation
```cpp
SecretBuffer::~SecretBuffer() {
    clear();
}

void SecretBuffer::clear() noexcept {
    if (!buffer_.empty()) {
        sodium_memzero(buffer_.data(), buffer_.size());
        buffer_.clear();
    }
}
```

### Viva Explanation
Ordinary memory deallocation (`delete` or `std::vector::clear()`) marks memory as free without erasing the bytes in RAM. `SecretBuffer` uses RAII so that whenever a key or temporary plaintext buffer goes out of scope—even if an exception occurs—its destructor calls `sodium_memzero()` to overwrite the sensitive bytes with zeroes before freeing the vector. Additionally, `IVaultStorage` declares a `virtual` destructor so deleting a `FileVaultStorage` through an `IVaultStorage*` pointer invokes the derived destructor safely.

---

## 7. Composition

### Simple Definition
Composition is a design relationship where a complex class is built by owning instances of other helper classes as member variables (a **"has-a"** relationship).

### Where It Is Implemented
- `CredentialVault` (`include/CredentialVault.h`)

### Code Snippet from Implementation
```cpp
class CredentialVault {
private:
    std::unique_ptr<IVaultStorage> storage_;
    CryptoService crypto_;
    SecretBuffer masterKey_;
    std::vector<unsigned char> salt_;
    std::vector<Credential> credentials_;
    bool isUnlocked_;
    bool hasUnsavedChanges_;
```

### Viva Explanation
Instead of making `CredentialVault` inherit from `CryptoService` or `SecretBuffer`, `CredentialVault` *has-a* `CryptoService`, *has-a* `SecretBuffer` for the active key, *has-a* `std::vector<Credential>` for the records, and *has-a* `std::unique_ptr<IVaultStorage>` for persistence. When `CredentialVault` is destroyed, all of its owned collaborators are automatically cleaned up.

---

## 8. File Handling

### Simple Definition
File handling is the reading and writing of persistent data on disk using C++ file streams (`std::ifstream`, `std::ofstream`) and filesystem utilities (`std::filesystem`).

### Where It Is Implemented
- `FileVaultStorage` (`src/FileVaultStorage.cpp`)

### Code Snippet from Implementation
```cpp
std::filesystem::path tempPath = filePath_;
tempPath += ".tmp";
{
    std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        lastError_ = "Failed to open temporary file '" + tempPath.string() + "' for writing.";
        return false;
    }
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    out.flush();
}
std::filesystem::rename(tempPath, filePath_, ec);
```

### Viva Explanation
`FileVaultStorage` reads and writes raw encrypted binary data using `std::ios::binary`. Before loading, it checks `std::filesystem::file_size()` against minimum (76 bytes) and maximum (1 MiB) limits so malformed files cannot cause huge memory allocations. When saving, it writes to `vault.dat.tmp`, verifies the stream state and written byte count, and only then replaces `vault.dat` via `std::filesystem::rename()` so a failed write never corrupts an existing vault.

---

## 9. Exception Handling

### Simple Definition
Exception handling uses `try`, `throw`, and `catch` blocks to detect and recover from runtime errors (such as invalid field lengths or initialization failures) cleanly without crashing the program or bypassing security checks.

### Where It Is Implemented
- `Credential::validateFields()` (`src/Credential.cpp`) throws `std::invalid_argument`
- `CredentialVault::addCredential()` and `editCredential()` (`src/CredentialVault.cpp`) catch `std::exception`
- `main()` (`src/main.cpp`) wraps application startup in a `try / catch` block

### Code Snippet from Implementation
```cpp
try {
    Credential::validateFields(label, username, password);
    if (isDuplicateLabel(label)) {
        lastError_ = "A credential with the label '" + label + "' already exists.";
        return false;
    }
    Credential record(nextId_++, label, username, password);
    credentials_.push_back(std::move(record));
    hasUnsavedChanges_ = true;
    return true;
} catch (const std::exception& ex) {
    lastError_ = ex.what();
    return false;
}
```

### Viva Explanation
When a user enters an empty label or a password longer than 256 characters, `Credential` throws `std::invalid_argument`. `CredentialVault` catches the exception, stores the descriptive message in `lastError_`, leaves the existing session untouched, and reports a friendly message in the terminal UI.
