#include "Credential.h"

#include <sodium.h>
#include <stdexcept>

namespace vault {

Credential::Credential()
    : id_(0), label_(), username_(), password_() {}

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

Credential::~Credential() {
    scrubPasswordMemory();
}

int Credential::getId() const {
    return id_;
}

const std::string& Credential::getLabel() const {
    return label_;
}

const std::string& Credential::getUsername() const {
    return username_;
}

const std::string& Credential::getPassword() const {
    return password_;
}

void Credential::setId(int id) {
    if (id <= 0) {
        throw std::invalid_argument("Credential ID must be a positive integer.");
    }
    id_ = id;
}

void Credential::setLabel(const std::string& label) {
    if (label.empty()) {
        throw std::invalid_argument("Website/Application label cannot be empty.");
    }
    if (label.size() > MAX_LABEL_LENGTH) {
        throw std::invalid_argument("Label exceeds maximum length of 128 characters.");
    }
    label_ = label;
}

void Credential::setUsername(const std::string& username) {
    if (username.empty()) {
        throw std::invalid_argument("Username cannot be empty.");
    }
    if (username.size() > MAX_USERNAME_LENGTH) {
        throw std::invalid_argument("Username exceeds maximum length of 128 characters.");
    }
    username_ = username;
}

void Credential::setPassword(const std::string& password) {
    if (password.empty()) {
        throw std::invalid_argument("Credential password cannot be empty.");
    }
    if (password.size() > MAX_PASSWORD_LENGTH) {
        throw std::invalid_argument("Credential password exceeds maximum length of 256 characters.");
    }
    scrubPasswordMemory();
    password_ = password;
}

void Credential::validateFields(const std::string& label,
                                const std::string& username,
                                const std::string& password) {
    if (label.empty() || label.size() > MAX_LABEL_LENGTH) {
        throw std::invalid_argument(
            "Label must be between 1 and " + std::to_string(MAX_LABEL_LENGTH) + " characters.");
    }
    if (username.empty() || username.size() > MAX_USERNAME_LENGTH) {
        throw std::invalid_argument(
            "Username must be between 1 and " + std::to_string(MAX_USERNAME_LENGTH) + " characters.");
    }
    if (password.empty() || password.size() > MAX_PASSWORD_LENGTH) {
        throw std::invalid_argument(
            "Password must be between 1 and " + std::to_string(MAX_PASSWORD_LENGTH) + " characters.");
    }
}

void Credential::scrubPasswordMemory() noexcept {
    if (!password_.empty()) {
        // Use libsodium's compiler-barrier memzero so the wipe is not optimized out
        sodium_memzero(&password_[0], password_.size());
        password_.clear();
    }
}

} // namespace vault
