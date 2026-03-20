#pragma once
#include "cipher.h"
#include <sstream>

// Template wrapper that encrypts/decrypts any streamable type
template <typename T>
class DataProtector {
    Cipher* cipher_;  // non-owning pointer — Vault owns the cipher
public:
    explicit DataProtector(Cipher* cipher) : cipher_(cipher) {}

    std::vector<uint8_t> protect(const T& value) const {
        std::ostringstream oss;
        oss << value;
        return cipher_->encrypt(oss.str());
    }

    T unprotect(std::vector<uint8_t> data) const {
        std::string raw = cipher_->decrypt(std::move(data));
        std::istringstream iss(raw);
        T value;
        iss >> value;
        return value;
    }
};

// Full string specialisation — avoids whitespace truncation from >>
template <>
class DataProtector<std::string> {
    Cipher* cipher_;
public:
    explicit DataProtector(Cipher* cipher) : cipher_(cipher) {}

    std::vector<uint8_t> protect(const std::string& value) const {
        return cipher_->encrypt(value);
    }

    std::string unprotect(std::vector<uint8_t> data) const {
        return cipher_->decrypt(std::move(data));
    }
};