#ifndef SECRET_BUFFER_H
#define SECRET_BUFFER_H

#include <cstddef>
#include <vector>

namespace vault {

/**
 * @class SecretBuffer
 * @brief RAII wrapper for sensitive cryptographic material (derived keys and
 *        serialized plaintext buffers).
 *
 * OOP Concepts Demonstrated:
 * - RAII (Resource Acquisition Is Initialization): Sensitive memory is acquired
 *   on construction/resize and guaranteed to be securely zeroed via
 *   sodium_memzero() when the object leaves scope or is destroyed.
 * - Encapsulation & Copy Prevention: Copy constructor and copy assignment are
 *   explicitly deleted (= delete) so secret keys are never duplicated by mistake.
 */
class SecretBuffer {
public:
    SecretBuffer();
    explicit SecretBuffer(std::size_t size);
    ~SecretBuffer();

    // Prevent accidental copying of sensitive material
    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;

    // Allow explicit move semantics
    SecretBuffer(SecretBuffer&& other) noexcept;
    SecretBuffer& operator=(SecretBuffer&& other) noexcept;

    /**
     * @brief Resizes the buffer, securely wiping any previous contents first.
     */
    void resize(std::size_t newSize);

    /**
     * @brief Securely zeroes the buffer contents and releases its length.
     */
    void clear() noexcept;

    unsigned char* data() noexcept;
    const unsigned char* data() const noexcept;
    std::size_t size() const noexcept;
    bool empty() const noexcept;

private:
    std::vector<unsigned char> buffer_;
};

} // namespace vault

#endif // SECRET_BUFFER_H
