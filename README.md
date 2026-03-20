# CryptVault

A console-based secure password manager written in C++17. Stores encrypted service credentials (URL, username, password) in a local binary vault file.

Built as a case study in polymorphic encryption, STL containers, C-style binary file I/O, move semantics, and templates.

---

## Features

- **Two encryption strategies** — XOR cipher (keyed from your master password) and Caesar cipher (custom shift per entry), selectable per credential
- **Per-credential cipher choice** — different services can use different ciphers
- **Template encryption layer** — `DataProtector<T>` wraps any streamable type
- **Persistent storage** — binary vault file using `fwrite`/`fread` with a magic header for format validation
- **Master password protection** — all reads and saves require authentication
- **Move semantics** — encrypted buffers are moved, never unnecessarily copied

---

## Project Structure

```
cryptvault/
├── cipher.h          # Cipher (abstract), XORCipher, CaesarCipher
├── credential.h      # Credential struct + CipherType enum
├── data_protector.h  # DataProtector<T> template
├── vault.h           # Vault class declaration
├── vault.cpp         # Vault implementation + binary file I/O
├── main.cpp          # Console UI
└── Makefile
```

---

## Build

Requires a C++17-capable compiler (GCC 7+ or Clang 5+).

```bash
make
```

Clean build artifacts:

```bash
make clean
```

---

## Usage

```bash
./cryptvault
```

On first launch you will be prompted for a master password. This password gates all reads and saves — there is no recovery if lost.

### Menu options

| Option | Action |
|--------|--------|
| `1` | Add a credential (service, URL, username, password + cipher choice) |
| `2` | Retrieve a decrypted password by service name |
| `3` | List all stored services and usernames (no passwords shown) |
| `4` | Save the vault to `vault.bin` |
| `5` | Load the vault from `vault.bin` |
| `6` | Run a `DataProtector<T>` demo |
| `0` | Exit |

### Typical session

```
./cryptvault
  Set master password: ••••••

  Choice: 5               ← load existing vault
  Choice: 2               ← retrieve a password
  Choice: 1               ← add a new credential
  Choice: 4               ← save before exiting
  Choice: 0
```

> **Important:** the vault is not auto-saved. Always use option `4` before exiting, or any changes made in the session will be lost.

---

## Cipher selection

When adding a credential you choose the encryption strategy:

```
Choose cipher for this credential:
  [1] XOR    (uses your master password as key)
  [2] Caesar — enter a shift value (1-255)
```

The cipher type and any parameters are stored alongside the encrypted password in the vault file, so decryption is always automatic — you never need to remember which cipher was used for which service.

---

## Vault file format (`vault.bin`)

The vault is a raw binary file with the following layout:

```
[4 bytes]  Magic: "CVT2"
[string]   Master password hash
[uint32]   Number of entries
  per entry:
    [string]   Service name
    [string]   URL
    [string]   Username
    [bytes]    Encrypted password
    [uint8]    Cipher type (1=XOR, 2=Caesar)
    [int32]    Cipher parameter (Caesar shift; 0 for XOR)
```

Strings are length-prefixed: a `uint32` byte count followed by the raw bytes. The magic header (`CVT2`) is checked on load — files from an older format version (`CVT1`) will be rejected with a clear error.

---

## Design notes

**Polymorphism** — `Cipher` is a pure abstract base class. `XORCipher` and `CaesarCipher` override `encrypt` and `decrypt`. The vault holds no cipher member itself; it calls `makeCipher()` to construct the right one on demand from each credential's stored metadata.

**Templates** — `DataProtector<T>` can encrypt any streamable type. A full specialisation for `std::string` avoids whitespace truncation from `operator>>`. The vault uses `DataProtector<std::string>` internally for all password encryption.

**Move semantics** — encrypted `std::vector<uint8_t>` buffers are moved into `Credential` on creation and moved again into `DataProtector::unprotect` on decryption, avoiding copies of sensitive data in memory.

**Exception safety** — all file operations check return values and throw `std::runtime_error` on failure, including truncated reads, bad magic bytes, and wrong master password.

---

## .gitignore

```gitignore
*.o
*.out
cryptvault
vault.bin
*.bin
.vscode/
.idea/
*.swp
*.swo
.DS_Store
```