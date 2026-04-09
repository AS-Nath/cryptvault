#pragma once
#include "credential.h"
#include "cipher.h"
#include "data_protector.h"
#include <map>
#include <string>
#include <memory>

class Vault {
    std::map<std::string, Credential> store_;
    std::string masterPasswordHash_;
    std::string xorKey_;  // derived from master password for XOR cipher

    static std::string hashPassword(const std::string& pwd);

    // Build a cipher from a credential's stored type/param
    std::unique_ptr<Cipher> makeCipher(CipherType ct, int param) const;

public:
    explicit Vault(const std::string& masterPassword);

    void authenticate(const std::string& masterPassword) const;

    // cipherType / cipherParam chosen per credential at add time
    void addCredential(const std::string& service,
                       const std::string& url,
                       const std::string& username,
                       const std::string& plainPassword,
                       CipherType ct,
                       int cipherParam = 0);

    std::string getPassword(const std::string& service,
                            const std::string& masterPassword) const;

    void listServices() const;

    void save(const std::string& filepath, const std::string& masterPassword) const;
    void load(const std::string& filepath, const std::string& masterPassword);

    bool empty() const { return store_.empty(); }
};