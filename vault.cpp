#include "vault.h"
#include <cstdio>
#include <stdexcept>
#include <iostream>

// ── file I/O helpers ──────────────────────────────────────────────────────────

static void writeStr(FILE* f, const std::string& s) {
    uint32_t len = static_cast<uint32_t>(s.size());
    std::fwrite(&len, sizeof(len), 1, f);
    if (len > 0) std::fwrite(s.data(), 1, len, f);
}

static std::string readStr(FILE* f) {
    uint32_t len = 0;
    if (std::fread(&len, sizeof(len), 1, f) != 1)
        throw std::runtime_error("File read error: truncated string length");
    if (len == 0) return {};
    std::string s(len, '\0');
    if (std::fread(s.data(), 1, len, f) != len)
        throw std::runtime_error("File read error: truncated string body");
    return s;
}

static void writeBytes(FILE* f, const std::vector<uint8_t>& v) {
    uint32_t len = static_cast<uint32_t>(v.size());
    std::fwrite(&len, sizeof(len), 1, f);
    if (len > 0) std::fwrite(v.data(), 1, len, f);
}

static std::vector<uint8_t> readBytes(FILE* f) {
    uint32_t len = 0;
    if (std::fread(&len, sizeof(len), 1, f) != 1)
        throw std::runtime_error("File read error: truncated byte length");
    std::vector<uint8_t> v(len);
    if (len > 0 && std::fread(v.data(), 1, len, f) != len)
        throw std::runtime_error("File read error: truncated byte body");
    return v;
}

// ── Vault ─────────────────────────────────────────────────────────────────────

std::string Vault::hashPassword(const std::string& pwd) {
    size_t h = 5381;
    for (unsigned char c : pwd) h = ((h << 5) + h) ^ c;
    return std::to_string(h);
}

// XOR key is derived from the master password so no separate key is needed
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

void Vault::save(const std::string& filepath,
                 const std::string& masterPassword) const {
    authenticate(masterPassword);
    FILE* f = std::fopen(filepath.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open file for writing: " + filepath);

    const char magic[] = "CVT2";  // bumped version — format changed
    std::fwrite(magic, 1, 4, f);
    writeStr(f, masterPasswordHash_);

    uint32_t count = static_cast<uint32_t>(store_.size());
    std::fwrite(&count, sizeof(count), 1, f);

    for (const auto& [svc, cred] : store_) {
        writeStr(f, svc);
        writeStr(f, cred.url);
        writeStr(f, cred.username);
        writeBytes(f, cred.encryptedPassword);
        uint8_t ct = static_cast<uint8_t>(cred.cipherType);
        std::fwrite(&ct, 1, 1, f);
        int32_t param = static_cast<int32_t>(cred.cipherParam);
        std::fwrite(&param, sizeof(param), 1, f);
    }

    std::fclose(f);
    std::cout << "[+] Vault saved to " << filepath << " (" << count << " entries)\n";
}

void Vault::load(const std::string& filepath,
                 const std::string& masterPassword) {
    FILE* f = std::fopen(filepath.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open file: " + filepath);

    char magic[5] = {};
    if (std::fread(magic, 1, 4, f) != 4 || std::string(magic, 4) != "CVT2") {
        std::fclose(f);
        throw std::runtime_error("Invalid or unsupported vault file (expected CVT2)");
    }

    std::string savedHash = readStr(f);
    if (savedHash != hashPassword(masterPassword)) {
        std::fclose(f);
        throw std::runtime_error("Authentication failed: incorrect master password");
    }

    uint32_t count = 0;
    if (std::fread(&count, sizeof(count), 1, f) != 1) {
        std::fclose(f);
        throw std::runtime_error("File read error: truncated entry count");
    }

    store_.clear();
    for (uint32_t i = 0; i < count; ++i) {
        std::string svc  = readStr(f);
        std::string url  = readStr(f);
        std::string user = readStr(f);
        auto encPwd      = readBytes(f);
        uint8_t ct = 0;
        if (std::fread(&ct, 1, 1, f) != 1) { std::fclose(f); throw std::runtime_error("File read error: cipher type"); }
        int32_t param = 0;
        if (std::fread(&param, sizeof(param), 1, f) != 1) { std::fclose(f); throw std::runtime_error("File read error: cipher param"); }
        store_[svc] = Credential(url, user, std::move(encPwd),
                                 static_cast<CipherType>(ct), param);
    }

    std::fclose(f);
    std::cout << "[+] Vault loaded from " << filepath
              << " (" << count << " entries)\n";
}