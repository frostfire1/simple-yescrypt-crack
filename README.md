# Multi-Threaded Yescrypt Password Cracker

A high-performance multi-threaded yescrypt password cracker with dictionary and brute force capabilities. Features true parallel execution across all CPU cores for maximum performance.

## Features

- **Multi-threaded execution** with automatic CPU core detection
- **Thread-safe cryptography** using `crypt_r()` for true parallel processing
- **Optimal password distribution** across threads for maximum efficiency
- **Dictionary attack** with configurable wordlists
- **Brute force attack** with customizable character length
- **Real-time progress** and performance monitoring
- **Scalable performance** - tested up to 16 threads with 4.3x speedup

## Performance

Performance benchmarks on a 16-core server:

| Threads | Execution Time | Speedup | CPU Utilization |
|---------|----------------|---------|-----------------|
| 1       | 45.1s         | 1.0x    | 100% (1 core)   |
| 2       | 28.3s         | 1.59x   | 178% (1.8 cores) |
| 4       | 16.7s         | 2.70x   | 322% (3.2 cores) |
| 8       | 11.9s         | 3.79x   | 543% (5.4 cores) |
| 16      | 10.5s         | 4.30x   | 718% (7.2 cores) |

## Requirements

- Linux (WSL recommended for Windows users)
- GCC/G++ with C++17 support
- yescrypt-1.1.0 library (download from https://www.openwall.com/yescrypt/)

## Quick Start

1. Install dependencies:
```bash
make install-deps
```

2. Download yescrypt-1.1.0 and extract to project folder

3. Build the cracker:
```bash
make
```

4. Run with shadow file and wordlist (auto-detect threads):
```bash
./yescrypt_cracker -s shadow.txt -w wordlist.txt
```

5. Run with specific thread count:
```bash
./yescrypt_cracker -s shadow.txt -w wordlist.txt -t 8
```

6. Run with brute force (up to 4 characters):
```bash
./yescrypt_cracker -s shadow.txt -b 4 -t 4
```

## Usage Options

```
./yescrypt_cracker [OPTIONS]

Options:
  -s, --shadow FILE     Shadow file to crack (required)
  -w, --wordlist FILE   Password wordlist file
  -b, --brute LENGTH    Enable brute force up to LENGTH characters
  -t, --threads NUM     Number of threads to use (default: auto-detect)
  -h, --help           Show help

Examples:
  ./yescrypt_cracker -s shadow.txt -w passwords.txt
  ./yescrypt_cracker -s shadow.txt -b 4 -t 8
  ./yescrypt_cracker -s shadow.txt -w passwords.txt -b 6 -t 4
  ./yescrypt_cracker -s shadow.txt -w passwords.txt -t 16
```

## Output Format

```
Using 8 threads for cracking...
Password distribution across 8 threads:
Thread 1: 128 passwords
Thread 2: 128 passwords
Thread 3: 128 passwords
Thread 4: 128 passwords
Thread 5: 128 passwords
Thread 6: 127 passwords
Thread 7: 127 passwords
Thread 8: 127 passwords
Total passwords: 1021

kali:kali
administrator:NOT_FOUND
Time: 11s
```

## Technical Implementation

- **Thread-safe cryptography**: Uses `crypt_r()` instead of `crypt()` for reentrant password verification
- **Smart password splitting**: Distributes passwords evenly across threads with optimal load balancing
- **Atomic synchronization**: Uses `std::atomic<bool>` for thread coordination without mutex overhead
- **Future/Promise pattern**: Efficient result collection from worker threads
- **Memory efficient**: Minimal memory overhead per thread

## Files

- `silent_yescrypt_cracker.cpp` - Main cracker source code
- `shadow.txt` - Sample shadow file with yescrypt hashes
- `10-million-password-list-top-1000000.txt` - Password wordlist
- `yescrypt-1.1.0/` - External yescrypt library (download separately)

## Legal Notice

For educational and authorized security testing only. Only use on systems you own or have explicit permission to test.

