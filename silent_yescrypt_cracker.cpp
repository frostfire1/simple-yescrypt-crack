#define _GNU_SOURCE  // Required for crypt_r - must be before includes
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>

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
    int numThreads;
    std::mutex outputMutex;
    std::atomic<bool> passwordFound;
    
public:
    YescryptCracker() : bruteForceMode(false), charset("abcdefghijklmnopqrstuvwxyz0123456789"), 
                       maxLength(6), numThreads(std::thread::hardware_concurrency()), passwordFound(false) {
        if (numThreads == 0) numThreads = 4; // fallback
    }
    
    void setBruteForce(bool enabled, int maxLen = 6) {
        bruteForceMode = enabled;
        maxLength = maxLen;
    }
    
    void setThreads(int threads) {
        if (threads > 0) {
            numThreads = threads;
        }
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
        // Use thread-safe crypt_r() instead of crypt() to allow true parallel execution
        struct crypt_data data;
        data.initialized = 0; // Initialize the struct
        
        char* result = crypt_r(password.c_str(), target.fullHash.c_str(), &data);
        if (result != nullptr) {
            return std::string(result) == target.fullHash;
        }
#endif
        return false;
    }
    
    // Thread worker function for dictionary attack
    void dictionaryWorker(const TargetHash& target, 
                         const std::vector<std::string>& passwordSubset,
                         std::promise<std::string>& result) {
        for (const auto& password : passwordSubset) {
            if (passwordFound.load()) break; // Another thread found it
            
            if (verifyPassword(password, target)) {
                passwordFound.store(true);
                result.set_value(password);
                return;
            }
        }
        result.set_value(""); // Not found in this subset
    }
    
    // Thread worker function for brute force attack
    void bruteForceWorker(const TargetHash& target,
                         const std::vector<std::string>& brutePasswords,
                         std::promise<std::string>& result) {
        for (const auto& password : brutePasswords) {
            if (passwordFound.load()) break; // Another thread found it
            
            if (verifyPassword(password, target)) {
                passwordFound.store(true);
                result.set_value(password);
                return;
            }
        }
        result.set_value(""); // Not found in this subset
    }
    
    // Split passwords into chunks for threads
    std::vector<std::vector<std::string>> splitPasswords(const std::vector<std::string>& passwords, int numChunks) {
        std::vector<std::vector<std::string>> chunks(numChunks);
        
        if (passwords.empty() || numChunks <= 0) return chunks;
        
        size_t totalPasswords = passwords.size();
        size_t baseChunkSize = totalPasswords / numChunks;
        size_t remainder = totalPasswords % numChunks;
        
        size_t currentIndex = 0;
        
        for (int i = 0; i < numChunks; ++i) {
            size_t chunkSize = baseChunkSize + (i < remainder ? 1 : 0);
            
            if (currentIndex < totalPasswords) {
                chunks[i].reserve(chunkSize);
                for (size_t j = 0; j < chunkSize && currentIndex < totalPasswords; ++j) {
                    chunks[i].push_back(passwords[currentIndex++]);
                }
            }
        }
        
        return chunks;
    }
    
    std::string crackTarget(const TargetHash& target) {
        passwordFound.store(false); // Reset for this target
        
        // Try dictionary attack first with multiple threads
        if (!passwords.empty()) {
            auto passwordChunks = splitPasswords(passwords, numThreads);
            
            // Debug output to show password distribution
            std::cout << "Password distribution across " << numThreads << " threads:" << std::endl;
            for (int i = 0; i < numThreads; ++i) {
                std::cout << "Thread " << (i+1) << ": " << passwordChunks[i].size() << " passwords" << std::endl;
            }
            std::cout << "Total passwords: " << passwords.size() << std::endl;
            
            std::vector<std::promise<std::string>> promises(numThreads);
            std::vector<std::future<std::string>> futures;
            std::vector<std::thread> threads;
            
            // Create futures from promises
            for (auto& promise : promises) {
                futures.push_back(promise.get_future());
            }
            
            // Launch threads
            for (int i = 0; i < numThreads; ++i) {
                if (!passwordChunks[i].empty()) {
                    threads.emplace_back(&YescryptCracker::dictionaryWorker, this,
                                       std::cref(target), std::cref(passwordChunks[i]),
                                       std::ref(promises[i]));
                } else {
                    promises[i].set_value(""); // Empty chunk
                }
            }
            
            // Wait for results
            for (auto& future : futures) {
                std::string result = future.get();
                if (!result.empty()) {
                    // Clean up threads
                    for (auto& thread : threads) {
                        if (thread.joinable()) thread.join();
                    }
                    return result;
                }
            }
            
            // Clean up threads
            for (auto& thread : threads) {
                if (thread.joinable()) thread.join();
            }
        }
        
        // Try brute force if enabled and dictionary failed
        if (bruteForceMode && !passwordFound.load()) {
            for (int len = 1; len <= maxLength; ++len) {
                std::vector<std::string> brutePasswords;
                generateBruteForce("", len, brutePasswords);
                
                if (!brutePasswords.empty()) {
                    passwordFound.store(false); // Reset for brute force
                    auto bruteChunks = splitPasswords(brutePasswords, numThreads);
                    
                    std::cout << "Brute force length " << len << " - distributing " << brutePasswords.size() 
                              << " passwords across " << numThreads << " threads" << std::endl;
                    
                    std::vector<std::promise<std::string>> brutePromises(numThreads);
                    std::vector<std::future<std::string>> bruteFutures;
                    std::vector<std::thread> bruteThreads;
                    
                    // Create futures from promises
                    for (auto& promise : brutePromises) {
                        bruteFutures.push_back(promise.get_future());
                    }
                    
                    // Launch threads
                    for (int i = 0; i < numThreads; ++i) {
                        if (!bruteChunks[i].empty()) {
                            bruteThreads.emplace_back(&YescryptCracker::bruteForceWorker, this,
                                                    std::cref(target), std::cref(bruteChunks[i]),
                                                    std::ref(brutePromises[i]));
                        } else {
                            brutePromises[i].set_value(""); // Empty chunk
                        }
                    }
                    
                    // Wait for results
                    for (auto& future : bruteFutures) {
                        std::string result = future.get();
                        if (!result.empty()) {
                            // Clean up threads
                            for (auto& thread : bruteThreads) {
                                if (thread.joinable()) thread.join();
                            }
                            return result;
                        }
                    }
                    
                    // Clean up threads
                    for (auto& thread : bruteThreads) {
                        if (thread.joinable()) thread.join();
                    }
                    
                    if (passwordFound.load()) break; // Found in this length
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
        
        std::cout << "Using " << numThreads << " threads for cracking..." << std::endl;
        
        for (const auto& target : targets) {
            std::string result = crackTarget(target);
            
            // Thread-safe output
            {
                std::lock_guard<std::mutex> lock(outputMutex);
                if (!result.empty()) {
                    std::cout << target.username << ":" << result << std::endl;
                } else {
                    std::cout << target.username << ":NOT_FOUND" << std::endl;
                }
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
              << "  -t, --threads NUM     Number of threads to use (default: auto-detect)\n"
              << "  -h, --help           Show this help\n"
              << "\nExamples:\n"
              << "  " << progName << " -s shadow.txt -w passwords.txt\n"
              << "  " << progName << " -s shadow.txt -b 4 -t 8\n"
              << "  " << progName << " -s shadow.txt -w passwords.txt -b 6 -t 4\n";
}

int main(int argc, char* argv[]) {
#if !HAS_REAL_CRYPT
    std::cout << "ERROR: Linux with crypt library required" << std::endl;
    return 1;
#endif

    std::string shadowFile, wordlistFile;
    bool bruteForce = false;
    int bruteLength = 4;
    int numThreads = 0; // 0 means auto-detect
    
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
        } else if (arg == "-t" || arg == "--threads") {
            if (i + 1 < argc) {
                numThreads = std::stoi(argv[++i]);
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
    
    if (numThreads > 0) {
        cracker.setThreads(numThreads);
    }
    
    cracker.addCommonPasswords();
    cracker.run();
    
    return 0;
}
