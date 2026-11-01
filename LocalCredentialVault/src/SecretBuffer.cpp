#include "SecretBuffer.h"

#include <sodium.h>
#include <utility>

namespace vault {

SecretBuffer::SecretBuffer() : buffer_() {}

SecretBuffer::SecretBuffer(std::size_t size) : buffer_(size, 0U) {}

SecretBuffer::~SecretBuffer() {
    clear();
}

SecretBuffer::SecretBuffer(SecretBuffer&& other) noexcept
    : buffer_(std::move(other.buffer_)) {}

SecretBuffer& SecretBuffer::operator=(SecretBuffer&& other) noexcept {
    if (this != &other) {
        clear();
        buffer_ = std::move(other.buffer_);
    }
    return *this;
}

void SecretBuffer::resize(std::size_t newSize) {
    clear();
    buffer_.assign(newSize, 0U);
}

void SecretBuffer::clear() noexcept {
    if (!buffer_.empty()) {
        sodium_memzero(buffer_.data(), buffer_.size());
        buffer_.clear();
    }
}

unsigned char* SecretBuffer::data() noexcept {
    return buffer_.empty() ? nullptr : buffer_.data();
}

const unsigned char* SecretBuffer::data() const noexcept {
    return buffer_.empty() ? nullptr : buffer_.data();
}

std::size_t SecretBuffer::size() const noexcept {
    return buffer_.size();
}

bool SecretBuffer::empty() const noexcept {
    return buffer_.empty();
}

} // namespace vault
