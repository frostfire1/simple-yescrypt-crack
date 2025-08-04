# Yescrypt Password Cracker

A high-performance yescrypt password cracker with dictionary and brute force capabilities.

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

4. Run with shadow file and wordlist:
```bash
./yescrypt_cracker -s shadow.txt -w wordlist.txt
```

5. Run with brute force (up to 4 characters):
```bash
./yescrypt_cracker -s shadow.txt -b 4
```

## Usage Options

```
./yescrypt_cracker [OPTIONS]

Options:
  -s, --shadow FILE     Shadow file to crack (required)
  -w, --wordlist FILE   Password wordlist file
  -b, --brute LENGTH    Enable brute force up to LENGTH characters
  -h, --help           Show help

Examples:
  ./yescrypt_cracker -s shadow.txt -w passwords.txt
  ./yescrypt_cracker -s shadow.txt -b 4
  ./yescrypt_cracker -s shadow.txt -w passwords.txt -b 6
```

## Output Format

```
username:password
username:NOT_FOUND
Time: 45s
```

## Files

- `silent_yescrypt_cracker.cpp` - Main cracker source code
- `shadow.txt` - Sample shadow file with yescrypt hashes
- `10-million-password-list-top-1000000.txt` - Password wordlist
- `yescrypt-1.1.0/` - External yescrypt library (download separately)

## Legal Notice

For educational and authorized security testing only. Only use on systems you own or have explicit permission to test.

