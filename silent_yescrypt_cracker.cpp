#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>

#ifdef __linux__
    #include <crypt.h>
    #include <cstring>
    #ifdef HAVE_YESCRYPT
        extern "C" {
            #include "yescrypt.h"
        }
        #define HAS_YESCRYPT_LIB 1
    #else
        #define HAS_YESCRYPT_LIB 0
    #endif
    #define HAS_REAL_CRYPT 1
#else
    #define HAS_REAL_CRYPT 0
    #define HAS_YESCRYPT_LIB 0
#endif

struct TargetHash {
    std::string username;
    std::string fullHash;
    std::string salt;
    std::string hashType;
};

class YescryptCracker {
private:
    std::vector<TargetHash> targets;
    std::vector<std::string> passwords;
    bool bruteForceMode;
    std::string charset;
    int maxLength;
    
public:
    YescryptCracker() : bruteForceMode(false), charset("abcdefghijklmnopqrstuvwxyz0123456789"), maxLength(6) {}
    
    void setBruteForce(bool enabled, int maxLen = 6) {
        bruteForceMode = enabled;
        maxLength = maxLen;
    }
    TargetHash parseShadowEntry(const std::string& line) {
        TargetHash target;
        size_t firstColon = line.find(':');
        if (firstColon == std::string::npos) return target;
        
        target.username = line.substr(0, firstColon);
        size_t secondColon = line.find(':', firstColon + 1);
        if (secondColon == std::string::npos) return target;
        
        target.fullHash = line.substr(firstColon + 1, secondColon - firstColon - 1);
        
        if (target.fullHash.substr(0, 3) == "$y$") {
            target.hashType = "yescrypt";
            size_t lastDollar = target.fullHash.rfind('$');
            if (lastDollar != std::string::npos && lastDollar > 3) {
                target.salt = target.fullHash.substr(0, lastDollar);
            }
        }
        
        return target;
    }
    
    bool loadTargets(const std::string& shadowFile) {
        std::ifstream file(shadowFile);
        if (!file.is_open()) return false;
        
        std::string line;
        while (std::getline(file, line)) {
            if (line.find(":$y$") != std::string::npos) {
                TargetHash target = parseShadowEntry(line);
                if (!target.username.empty() && !target.fullHash.empty()) {
                    targets.push_back(target);
                }
            }
        }
        
        return !targets.empty();
    }
    
    bool loadPasswordList(const std::string& passwordFile) {
        if (passwordFile.empty()) return true;
        
        std::ifstream file(passwordFile);
        if (!file.is_open()) return false;
        
        std::string password;
        while (std::getline(file, password)) {
            if (!password.empty()) {
                passwords.push_back(password);
            }
        }
        
        return true;
    }
    
    void addCommonPasswords() {
        std::vector<std::string> common = {
            "password", "123456", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "admin", "root", "toor", "login", "pass"
        };
        
        passwords.insert(passwords.begin(), common.begin(), common.end());
        
        // Add username-based passwords
        for (const auto& target : targets) {
            passwords.insert(passwords.begin(), target.username);
            passwords.insert(passwords.begin(), target.username + "123");
            passwords.insert(passwords.begin(), target.username + "1");
        }
    }
    
    void generateBruteForce(const std::string& current, int length, std::vector<std::string>& results) {
        if (current.length() == length) {
            results.push_back(current);
            return;
        }
        
        for (char c : charset) {
            generateBruteForce(current + c, length, results);
            if (results.size() > 1000000) break; // Limit brute force
        }
    }
    
    bool verifyPassword(const std::string& password, const TargetHash& target) {
#if HAS_YESCRYPT_LIB || HAS_REAL_CRYPT
        char* result = crypt(password.c_str(), target.fullHash.c_str());
        if (result != nullptr) {
            return std::string(result) == target.fullHash;
        }
#endif
        return false;
    }
    
    std::string crackTarget(const TargetHash& target) {
        // Try dictionary attack first
        for (const std::string& password : passwords) {
            if (verifyPassword(password, target)) {
                return password;
            }
        }
        
        // Try brute force if enabled
        if (bruteForceMode) {
            for (int len = 1; len <= maxLength; ++len) {
                std::vector<std::string> brutePasswords;
                generateBruteForce("", len, brutePasswords);
                
                for (const std::string& password : brutePasswords) {
                    if (verifyPassword(password, target)) {
                        return password;
                    }
                }
            }
        }
        
        return "";
    }
    
    void run() {
#if !HAS_REAL_CRYPT
        std::cout << "ERROR: Requires Linux with crypt library support" << std::endl;
        return;
#endif

        auto totalStart = std::chrono::high_resolution_clock::now();
        
        for (const auto& target : targets) {
            std::string result = crackTarget(target);
            if (!result.empty()) {
                std::cout << target.username << ":" << result << std::endl;
            } else {
                std::cout << target.username << ":NOT_FOUND" << std::endl;
            }
        }
        
        auto totalEnd = std::chrono::high_resolution_clock::now();
        auto totalDuration = std::chrono::duration_cast<std::chrono::seconds>(totalEnd - totalStart);
        
        std::cout << "Time: " << totalDuration.count() << "s" << std::endl;
    }
};

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [OPTIONS]\n"
              << "Options:\n"
              << "  -s, --shadow FILE     Shadow file to crack (required)\n"
              << "  -w, --wordlist FILE   Password wordlist file\n"
              << "  -b, --brute LENGTH    Enable brute force up to LENGTH characters\n"
              << "  -h, --help           Show this help\n"
              << "\nExamples:\n"
              << "  " << progName << " -s shadow.txt -w passwords.txt\n"
              << "  " << progName << " -s shadow.txt -b 4\n"
              << "  " << progName << " -s shadow.txt -w passwords.txt -b 6\n";
}

int main(int argc, char* argv[]) {
#if !HAS_REAL_CRYPT
    std::cout << "ERROR: Linux with crypt library required" << std::endl;
    return 1;
#endif

    std::string shadowFile, wordlistFile;
    bool bruteForce = false;
    int bruteLength = 4;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-s" || arg == "--shadow") {
            if (i + 1 < argc) shadowFile = argv[++i];
        } else if (arg == "-w" || arg == "--wordlist") {
            if (i + 1 < argc) wordlistFile = argv[++i];
        } else if (arg == "-b" || arg == "--brute") {
            bruteForce = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                bruteLength = std::stoi(argv[++i]);
            }
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    if (shadowFile.empty()) {
        std::cout << "ERROR: Shadow file required\n";
        printUsage(argv[0]);
        return 1;
    }

    YescryptCracker cracker;
    
    if (!cracker.loadTargets(shadowFile)) {
        std::cout << "ERROR: Cannot load shadow file: " << shadowFile << std::endl;
        return 1;
    }
    
    if (!wordlistFile.empty() && !cracker.loadPasswordList(wordlistFile)) {
        std::cout << "ERROR: Cannot load wordlist: " << wordlistFile << std::endl;
        return 1;
    }
    
    if (bruteForce) {
        cracker.setBruteForce(true, bruteLength);
    }
    
    cracker.addCommonPasswords();
    cracker.run();
    
    return 0;
}
