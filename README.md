# CryptVault

A console-based password manager written in C++17. Credentials (service name, URL, username, password) are encrypted and stored in a local binary vault file — no cloud, no dependencies, no third-party libraries.

Built as a case study for BACSE104 (Structured and Object-Oriented Programming) at VIT Vellore.

---

## Features

- **Pluggable cipher strategy** — choose XOR (keyed from your master password) or Caesar cipher (custom shift) per credential; different services can use different ciphers
- **Template encryption layer** — `DataProtector<T>` wraps any streamable type; a full specialisation for `std::string` handles whitespace-safe round-trips
- **Persistent binary vault** — `vault.bin` uses `fwrite`/`fread` with a `CVT2` magic header for format validation
- **Master password protection** — authentication is required before any save, load, or password retrieval; passwords are never stored in plaintext
- **Move-safe buffers** — encrypted `std::vector<uint8_t>` payloads are moved, never unnecessarily copied
- **Exception-safe I/O** — all file operations throw `std::runtime_error` on failure (truncated reads, bad magic, wrong password)

---

## Project Structure

```
cryptvault/
├── cipher.h          # Cipher (abstract), XORCipher, CaesarCipher
├── credential.h      # Credential struct + CipherType enum
├── data_protector.h  # DataProtector<T> template + std::string specialisation
├── vault.h           # Vault class declaration
├── vault.cpp         # Vault implementation (add, get, list, save, load)
├── vault_io.h        # C helper declarations (cv_write_str, cv_read_bytes, …)
├── vault_io.c        # C helper implementations
├── main.cpp          # Console UI (banner, menu loop, cipher selection)
└── Makefile
```

---

## Build

Requires a C++17-capable compiler (GCC 7+ or Clang 5+).

```bash
make
```

Remove build artifacts:

```bash
make clean
```

---

## Usage

```bash
./cryptvault
```

On first launch you will be prompted to set a master password. This password is hashed and stored in the vault file header — **there is no recovery mechanism if it is lost**.

### Menu

| Option | Action |
|--------|--------|
| `1` | Add a credential (service name, URL, username, password, cipher choice) |
| `2` | Retrieve a decrypted password by service name |
| `3` | List all stored services and usernames (passwords never shown) |
| `4` | Save the vault to `vault.bin` |
| `5` | Load the vault from `vault.bin` |
| `0` | Exit |

> **Note:** the vault is not auto-saved. Always use option `4` before exiting, or unsaved changes will be lost.

### Typical session

```
./cryptvault

  ╔══════════════════════════════╗
  ║       CryptVault v1.0        ║
  ║   Secure Password Manager    ║
  ╚══════════════════════════════╝

  Set master password: ••••••••••••
  Vault ready.

  Choice: 5               ← load an existing vault
  Choice: 1               ← add a new credential
  Choice: 2               ← retrieve a password
  Choice: 4               ← save before exiting
  Choice: 0
```

---

## Cipher Selection

When adding a credential you choose the encryption strategy:

```
Choose cipher for this credential:
  [1] XOR    (uses your master password as key)
  [2] Caesar — enter a shift value (1-255)
```

The cipher type and any parameters are stored alongside the encrypted password in the vault file, so decryption is automatic — you never need to remember which cipher was used for which entry.

---

## Vault File Format (`vault.bin`)

The vault is a raw binary file with the following layout:

```
[4 bytes]   Magic: "CVT2"
[string]    Master password hash (djb2, stored as a decimal string)
[uint32]    Number of entries
  per entry:
    [string]    Service name
    [string]    URL
    [string]    Username
    [bytes]     Encrypted password
    [uint8]     Cipher type  (1 = XOR, 2 = Caesar)
    [int32]     Cipher parameter  (Caesar shift; 0 for XOR)
```

All strings are length-prefixed: a `uint32` byte count followed by the raw bytes (`cv_write_str` / `cv_read_str`). Encrypted byte buffers follow the same length-prefix convention (`cv_write_bytes` / `cv_read_bytes`).

The `CVT2` magic header is verified on every load. Files produced by the older `CVT1` format are rejected with a clear error message.

---

## Design Notes

**Polymorphism** — `Cipher` is a pure abstract base class with `encrypt` and `decrypt` as pure virtual methods. `XORCipher` and `CaesarCipher` each override both. The `Vault` class holds no `Cipher` member directly; instead it calls `makeCipher()` on demand, constructing the right subclass from each credential's stored metadata.

**Templates** — `DataProtector<T>` can encrypt any type that is readable/writable via `std::ostringstream`/`std::istringstream`. The explicit `DataProtector<std::string>` specialisation bypasses `operator>>` entirely, avoiding whitespace truncation for passwords that contain spaces.

**Move semantics** — encrypted `std::vector<uint8_t>` buffers are `std::move`d into `Credential` on creation and into `DataProtector::unprotect` on retrieval, keeping sensitive data from being copied unnecessarily.

**Mixed-language I/O** — low-level file helpers (`cv_write_str`, `cv_read_str`, `cv_write_bytes`, `cv_read_bytes`) are implemented in plain C (`vault_io.c`), demonstrating C-linkage interop with a C++ codebase via `extern "C"` declarations in `vault_io.h`.

---

## Security Considerations

This project is a **learning exercise**, not a production-grade security tool. A few things to be aware of:

- The master password is hashed with a simple djb2 variant, not a proper password-hashing algorithm (bcrypt, Argon2, etc.).
- XOR and Caesar ciphers are not cryptographically secure. They are included to demonstrate polymorphism and template design patterns.
- Encrypted data is stored in a local binary file with no access controls beyond the file system.

For any real-world secrets, use a production password manager.

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