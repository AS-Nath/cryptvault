#include "vault.h"
#include "vault_io.h"
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <iostream>

// ── Vault ─────────────────────────────────────────────────────────────────────

std::string Vault::hashPassword(const std::string& pwd) {
    size_t h = 5381;
    for (unsigned char c : pwd) h = ((h << 5) + h) ^ c;
    return std::to_string(h);
}

Vault::Vault(const std::string& masterPassword)
    : masterPasswordHash_(hashPassword(masterPassword)),
      xorKey_(masterPassword) {}

std::unique_ptr<Cipher> Vault::makeCipher(CipherType ct, int param) const {
    switch (ct) {
        case CipherType::XOR:    return std::make_unique<XORCipher>(xorKey_);
        case CipherType::Caesar: return std::make_unique<CaesarCipher>(param);
        default: throw std::runtime_error("Unknown cipher type");
    }
}

void Vault::authenticate(const std::string& masterPassword) const {
    if (hashPassword(masterPassword) != masterPasswordHash_)
        throw std::runtime_error("Authentication failed: incorrect master password");
}

void Vault::addCredential(const std::string& service,
                          const std::string& url,
                          const std::string& username,
                          const std::string& plainPassword,
                          CipherType ct,
                          int cipherParam) {
    auto cipher = makeCipher(ct, cipherParam);
    DataProtector<std::string> protector(cipher.get());
    auto encPwd = protector.protect(plainPassword);

    store_[service] = Credential(url, username, std::move(encPwd), ct, cipherParam);

    const char* name = (ct == CipherType::XOR) ? "XOR" : "Caesar";
    std::cout << "[+] Stored credentials for \"" << service
              << "\" (cipher: " << name << ")\n";
}

std::string Vault::getPassword(const std::string& service,
                               const std::string& masterPassword) const {
    authenticate(masterPassword);
    auto it = store_.find(service);
    if (it == store_.end())
        throw std::runtime_error("Service not found: " + service);

    const Credential& cred = it->second;
    auto cipher = makeCipher(cred.cipherType, cred.cipherParam);
    DataProtector<std::string> protector(cipher.get());
    return protector.unprotect(cred.encryptedPassword);
}

void Vault::listServices() const {
    if (store_.empty()) { std::cout << "  (vault is empty)\n"; return; }
    for (const auto& [svc, cred] : store_) {
        const char* name = (cred.cipherType == CipherType::XOR) ? "XOR" : "Caesar";
        std::cout << "  • " << svc << " — " << cred.username
                  << " (" << cred.url << ")  [" << name << "]\n";
    }
}

// ── save ──────────────────────────────────────────────────────────────────────

void Vault::save(const std::string& filepath,
                 const std::string& masterPassword) const {
    authenticate(masterPassword);

    FILE* f = std::fopen(filepath.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open file for writing: " + filepath);

    /* magic + master hash */
    const char magic[] = "CVT2";
    if (std::fwrite(magic, 1, 4, f) != 4) goto write_err;

    {
        const std::string& h = masterPasswordHash_;
        if (cv_write_str(f, h.c_str(), static_cast<uint32_t>(h.size())) != 0)
            goto write_err;

        uint32_t count = static_cast<uint32_t>(store_.size());
        if (std::fwrite(&count, sizeof(count), 1, f) != 1) goto write_err;

        for (const auto& [svc, cred] : store_) {
            if (cv_write_str(f, svc.c_str(),          static_cast<uint32_t>(svc.size()))          != 0) goto write_err;
            if (cv_write_str(f, cred.url.c_str(),     static_cast<uint32_t>(cred.url.size()))     != 0) goto write_err;
            if (cv_write_str(f, cred.username.c_str(),static_cast<uint32_t>(cred.username.size()))!= 0) goto write_err;
            if (cv_write_bytes(f, cred.encryptedPassword.data(),
                               static_cast<uint32_t>(cred.encryptedPassword.size()))              != 0) goto write_err;

            uint8_t  ct    = static_cast<uint8_t>(cred.cipherType);
            int32_t  param = static_cast<int32_t>(cred.cipherParam);
            if (std::fwrite(&ct,    1,           1, f) != 1) goto write_err;
            if (std::fwrite(&param, sizeof(param),1, f) != 1) goto write_err;
        }
    }

    std::fclose(f);
    std::cout << "[+] Vault saved to " << filepath
              << " (" << store_.size() << " entries)\n";
    return;

write_err:
    std::fclose(f);
    throw std::runtime_error("Write error while saving vault");
}

// ── load ──────────────────────────────────────────────────────────────────────

void Vault::load(const std::string& filepath,
                 const std::string& masterPassword) {
    FILE* f = std::fopen(filepath.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open file: " + filepath);

    /* verify magic */
    char magic[5] = {};
    if (std::fread(magic, 1, 4, f) != 4 || std::string(magic, 4) != "CVT2") {
        std::fclose(f);
        throw std::runtime_error("Invalid or unsupported vault file (expected CVT2)");
    }

    /* verify master password */
    char*    hashBuf = nullptr;
    uint32_t hashLen = 0;
    if (cv_read_str(f, &hashBuf, &hashLen) != 0) {
        std::fclose(f);
        throw std::runtime_error("File read error: master hash");
    }
    std::string savedHash(hashBuf, hashLen);
    std::free(hashBuf);

    if (savedHash != hashPassword(masterPassword)) {
        std::fclose(f);
        throw std::runtime_error("Authentication failed: incorrect master password");
    }

    /* entry count */
    uint32_t count = 0;
    if (std::fread(&count, sizeof(count), 1, f) != 1) {
        std::fclose(f);
        throw std::runtime_error("File read error: entry count");
    }

    store_.clear();

    for (uint32_t i = 0; i < count; ++i) {
        char*    s = nullptr; uint32_t sl = 0;
        char*    u = nullptr; uint32_t ul = 0;
        char*    n = nullptr; uint32_t nl = 0;
        uint8_t* b = nullptr; uint32_t bl = 0;
        uint8_t  ct    = 0;   /* hoisted — goto cannot cross initialisations in C++ */
        int32_t  param = 0;

        if (cv_read_str(f,   &s, &sl) != 0) goto read_err;
        if (cv_read_str(f,   &u, &ul) != 0) { std::free(s); goto read_err; }
        if (cv_read_str(f,   &n, &nl) != 0) { std::free(s); std::free(u); goto read_err; }
        if (cv_read_bytes(f, &b, &bl) != 0) { std::free(s); std::free(u); std::free(n); goto read_err; }

        if (std::fread(&ct,    1,            1, f) != 1) { std::free(s); std::free(u); std::free(n); std::free(b); goto read_err; }
        if (std::fread(&param, sizeof(param),1, f) != 1) { std::free(s); std::free(u); std::free(n); std::free(b); goto read_err; }

        {
            std::string svc(s, sl);
            std::vector<uint8_t> encPwd(b, b + bl);
            store_[svc] = Credential(
                std::string(u, ul),
                std::string(n, nl),
                std::move(encPwd),
                static_cast<CipherType>(ct), param
            );
        }

        std::free(s); std::free(u); std::free(n); std::free(b);
        continue;

read_err:
        std::fclose(f);
        throw std::runtime_error("File read error: truncated entry " + std::to_string(i));
    }

    std::fclose(f);
    std::cout << "[+] Vault loaded from " << filepath
              << " (" << count << " entries)\n";
}