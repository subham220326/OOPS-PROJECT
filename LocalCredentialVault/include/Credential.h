#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <cstddef>
#include <string>

namespace vault {

/**
 * @class Credential
 * @brief Represents a single stored website/application login credential.
 *
 * OOP Concepts Demonstrated:
 * - Encapsulation: All record fields (id, label, username, password) are kept
 *   private and accessed or updated exclusively through validated public
 *   getters and setters.
 * - Constructors & Destructor: Initializes member fields cleanly and zeroes
 *   the internal password buffer when a Credential object is destroyed.
 */
class Credential {
public:
    // Reasonable field length bounds to keep parsing and memory predictable
    static constexpr std::size_t MAX_LABEL_LENGTH = 128;
    static constexpr std::size_t MAX_USERNAME_LENGTH = 128;
    static constexpr std::size_t MAX_PASSWORD_LENGTH = 256;

    /**
     * @brief Default constructor creating an empty record with ID 0.
     */
    Credential();

    /**
     * @brief Parameterized constructor with validation.
     * @throws std::invalid_argument if any field violates length constraints.
     */
    Credential(int id,
               const std::string& label,
               const std::string& username,
               const std::string& password);

    /**
     * @brief Destructor that scrubs the in-memory password string before release.
     */
    ~Credential();

    // Copy and move operations
    Credential(const Credential& other) = default;
    Credential& operator=(const Credential& other) = default;
    Credential(Credential&& other) noexcept = default;
    Credential& operator=(Credential&& other) noexcept = default;

    // Controlled Getters (const-correct so callers cannot mutate internals)
    int getId() const;
    const std::string& getLabel() const;
    const std::string& getUsername() const;
    const std::string& getPassword() const;

    // Controlled Setters with input validation
    void setId(int id);
    void setLabel(const std::string& label);
    void setUsername(const std::string& username);
    void setPassword(const std::string& password);

    /**
     * @brief Validates whether a label, username, and password meet length rules.
     */
    static void validateFields(const std::string& label,
                               const std::string& username,
                               const std::string& password);

private:
    int id_;
    std::string label_;
    std::string username_;
    std::string password_;

    void scrubPasswordMemory() noexcept;
};

} // namespace vault

#endif // CREDENTIAL_H
