#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

// Abstract base class — polymorphic encryption interface
class Cipher {
public:
    virtual std::vector<uint8_t> encrypt(const std::string& data) = 0;
    virtual std::string decrypt(std::vector<uint8_t> data) = 0;
    virtual ~Cipher() = default;
};

// XOR cipher — XORs each byte against a repeating key
class XORCipher : public Cipher {
    std::string key_;
public:
    explicit XORCipher(const std::string& key) : key_(key) {
        if (key.empty()) throw std::invalid_argument("XORCipher: key must not be empty");
    }

    std::vector<uint8_t> encrypt(const std::string& data) override {
        std::vector<uint8_t> out(data.size());
        for (size_t i = 0; i < data.size(); ++i)
            out[i] = static_cast<uint8_t>(data[i]) ^ static_cast<uint8_t>(key_[i % key_.size()]);
        return out;
    }

    std::string decrypt(std::vector<uint8_t> data) override {
        // XOR is its own inverse
        std::string out(data.size(), '\0');
        for (size_t i = 0; i < data.size(); ++i)
            out[i] = static_cast<char>(data[i] ^ static_cast<uint8_t>(key_[i % key_.size()]));
        return out;
    }
};

// Caesar cipher — shifts each byte by a fixed offset
class CaesarCipher : public Cipher {
    int shift_;
public:
    explicit CaesarCipher(int shift) : shift_(shift & 0xFF) {}

    std::vector<uint8_t> encrypt(const std::string& data) override {
        std::vector<uint8_t> out(data.size());
        for (size_t i = 0; i < data.size(); ++i)
            out[i] = static_cast<uint8_t>((static_cast<uint8_t>(data[i]) + shift_) & 0xFF);
        return out;
    }

    std::string decrypt(std::vector<uint8_t> data) override {
        std::string out(data.size(), '\0');
        for (size_t i = 0; i < data.size(); ++i)
            out[i] = static_cast<char>((data[i] - shift_ + 256) & 0xFF);
        return out;
    }
};
