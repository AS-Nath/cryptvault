#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class CipherType : uint8_t {
    XOR    = 1,
    Caesar = 2
};

struct Credential {
    std::string url;
    std::string username;
    std::vector<uint8_t> encryptedPassword;
    CipherType  cipherType  = CipherType::XOR;
    int         cipherParam = 0;  // XOR: unused (key is master pwd), Caesar: shift value

    Credential() = default;

    Credential(std::string url_, std::string username_,
               std::vector<uint8_t> encPwd,
               CipherType ct, int param)
        : url(std::move(url_)),
          username(std::move(username_)),
          encryptedPassword(std::move(encPwd)),
          cipherType(ct),
          cipherParam(param) {}

    Credential(const Credential&) = default;
    Credential& operator=(const Credential&) = default;
    Credential(Credential&&) = default;
    Credential& operator=(Credential&&) = default;
};