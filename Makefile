# Yescrypt Password Cracker Makefile
# Clean and optimized for Linux with yescrypt-1.1.0 integration

CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -mtune=native -pthread -Wall -Wextra
LDFLAGS = -pthread
YESCRYPT_DIR = yescrypt-1.1.0
YESCRYPT_OBJS = $(YESCRYPT_DIR)/yescrypt-opt.o $(YESCRYPT_DIR)/yescrypt-common.o $(YESCRYPT_DIR)/sha256.o $(YESCRYPT_DIR)/insecure_memzero.o

# Default target
all: yescrypt_cracker

# Build the yescrypt cracker
yescrypt_cracker: silent_yescrypt_cracker.cpp yescrypt_lib
	@echo "🔨 Building yescrypt cracker with external library..."
	$(CXX) $(CXXFLAGS) -DHAVE_YESCRYPT -I$(YESCRYPT_DIR) \
		-o $@ $< $(YESCRYPT_OBJS) \
		$(LDFLAGS) -lcrypt -lrt -fopenmp
	@echo "✅ Build complete: $@"

# Build yescrypt library
yescrypt_lib:
	@echo "📥 Building yescrypt-1.1.0 library..."
	@if [ ! -d "$(YESCRYPT_DIR)" ]; then \
		echo "❌ $(YESCRYPT_DIR) folder not found!"; \
		echo "Please download from: https://www.openwall.com/yescrypt/"; \
		exit 1; \
	fi
	@cd $(YESCRYPT_DIR) && make clean > /dev/null 2>&1 && make > /dev/null 2>&1
	@echo "✅ yescrypt library ready"

# Run the cracker
run: yescrypt_cracker
	@echo "� Running yescrypt cracker..."
	@echo "Usage: ./yescrypt_cracker -s shadow.txt -w wordlist.txt"
	@echo "       ./yescrypt_cracker -s shadow.txt -b 4"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build files..."
	@rm -f yescrypt_cracker
	@if [ -d "$(YESCRYPT_DIR)" ]; then \
		cd $(YESCRYPT_DIR) && make clean > /dev/null 2>&1; \
	fi
	@echo "✅ Clean complete"

# Install dependencies
install-deps:
	@echo "📦 Installing dependencies..."
	@sudo apt update
	@sudo apt install -y gcc g++ libcrypt-dev build-essential
	@echo "✅ Dependencies installed"

# Help
help:
	@echo "Yescrypt Password Cracker"
	@echo "========================"
	@echo "Targets:"
	@echo "  all          - Build the cracker (default)"
	@echo "  yescrypt_cracker - Build the main cracker"
	@echo "  run          - Show usage examples"
	@echo "  clean        - Clean build files"
	@echo "  install-deps - Install required packages"
	@echo "  help         - Show this help"

.PHONY: all yescrypt_cracker yescrypt_lib run clean install-deps help
