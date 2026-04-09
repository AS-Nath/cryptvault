#include <iostream>
#include <string>
#include <limits>
#include <memory>
#include "cipher.h"
#include "vault.h"

static void clearInput() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

static std::string prompt(const std::string& label) {
    std::cout << "  " << label << ": ";
    std::string val;
    std::getline(std::cin, val);
    return val;
}

static void printBanner() {
    std::cout << "\n"
              << "  ╔══════════════════════════════╗\n"
              << "  ║       CryptVault v1.0        ║\n"
              << "  ║   Secure Password Manager    ║\n"
              << "  ╚══════════════════════════════╝\n\n";
}

static void printMenu() {
    std::cout << "\n"
              << "  [1] Add credential\n"
              << "  [2] Retrieve password\n"
              << "  [3] List services\n"
              << "  [4] Save vault\n"
              << "  [5] Load vault\n"
              << "  [0] Exit\n"
              << "\n  Choice: ";
}

// Ask the user which cipher to use and return type + param
static std::pair<CipherType, int> chooseCipher() {
    std::cout << "\n  Choose cipher for this credential:\n"
              << "    [1] XOR  (uses your master password as key)\n"
              << "    [2] Caesar — enter a shift value (1-255)\n"
              << "  Choice: ";
    int c;
    std::cin >> c;
    clearInput();

    if (c == 2) {
        std::cout << "  Shift value (1-255): ";
        int shift;
        std::cin >> shift;
        clearInput();
        shift = std::max(1, std::min(255, shift));
        return {CipherType::Caesar, shift};
    }
    return {CipherType::XOR, 0};
}

int main(void) {
    printBanner();

    std::string masterPwd = prompt("Set master password");
    if (masterPwd.empty()) {
        std::cerr << "  [!] Master password cannot be empty. Exiting.\n";
        return 1;
    }

    Vault vault(masterPwd);
    std::cout << "  Vault ready.\n";

    const std::string vaultFile = "vault.bin";
    int choice = -1;

    while (true) {
        printMenu();
        std::cin >> choice;
        clearInput();

        try {
            switch (choice) {
            case 1: {
                std::string svc  = prompt("Service name (e.g. github)");
                std::string url  = prompt("URL");
                std::string user = prompt("Username");
                std::string pwd  = prompt("Password");
                auto [ct, param] = chooseCipher();
                vault.addCredential(svc, url, user, pwd, ct, param);
                break;
            }
            case 2: {
                std::string svc = prompt("Service name");
                std::string mp  = prompt("Master password");
                std::string pwd = vault.getPassword(svc, mp);
                std::cout << "  Password for \"" << svc << "\": " << pwd << "\n";
                break;
            }
            case 3:
                std::cout << "\n  Stored services:\n";
                vault.listServices();
                break;
            case 4: {
                std::string mp = prompt("Master password to save");
                vault.save(vaultFile, mp);
                break;
            }
            case 5: {
                std::string mp = prompt("Master password to load");
                vault.load(vaultFile, mp);
                break;
            }
            case 0:
                std::cout << "  Goodbye.\n";
                return 0;
            default:
                std::cout << "  Unknown option.\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "  [!] Error: " << e.what() << "\n";
        }
    }
}