# DDoS Protection System - Optimized Makefile
# Production-ready build with aggressive optimizations

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -mtune=native -flto
CFLAGS += -fomit-frame-pointer -funroll-loops -ftree-vectorize
CFLAGS += -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS += -fstack-protector-strong -fPIC
CFLAGS += -pthread

# Debug build options (use: make DEBUG=1)
ifdef DEBUG
	CFLAGS = -Wall -Wextra -g -O0 -DDEBUG -pthread
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

# Libraries
LDFLAGS = -pthread -lm
LIBS = -lpcap -ljansson -lpthread -lm

# Optional libraries (install if available)
LIBS += $(shell pkg-config --libs libmicrohttpd 2>/dev/null || echo "")
LIBS += $(shell pkg-config --libs libmaxminddb 2>/dev/null || echo "")
LIBS += $(shell pkg-config --libs libbpf 2>/dev/null || echo "")

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# Source files
CORE_SRC = $(wildcard $(SRC_DIR)/core/*.c)
PACKET_SRC = $(wildcard $(SRC_DIR)/packet/*.c)
DETECTION_SRC = $(wildcard $(SRC_DIR)/detection/*.c)
FILTER_SRC = $(wildcard $(SRC_DIR)/filter/*.c)
STORAGE_SRC = $(wildcard $(SRC_DIR)/storage/*.c)
API_SRC = $(wildcard $(SRC_DIR)/api/*.c)
GEOIP_SRC = $(wildcard $(SRC_DIR)/geoip/*.c)

ALL_SRC = $(CORE_SRC) $(PACKET_SRC) $(DETECTION_SRC) $(FILTER_SRC) \
          $(STORAGE_SRC) $(API_SRC) $(GEOIP_SRC)

# Object files
OBJ = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ALL_SRC))

# Target binary
TARGET = $(BIN_DIR)/ddos-protect

# eBPF programs
EBPF_SRC = ebpf/xdp_filter.c
EBPF_OBJ = ebpf/xdp_filter.o

.PHONY: all clean install uninstall test

all: directories $(TARGET) ebpf

directories:
	@mkdir -p $(OBJ_DIR)/core $(OBJ_DIR)/packet $(OBJ_DIR)/detection
	@mkdir -p $(OBJ_DIR)/filter $(OBJ_DIR)/storage $(OBJ_DIR)/api
	@mkdir -p $(OBJ_DIR)/geoip $(BIN_DIR)

$(TARGET): $(OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Build complete: $@"
	@ls -lh $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# eBPF/XDP programs
ebpf: $(EBPF_OBJ)

$(EBPF_OBJ): $(EBPF_SRC)
	@echo "Compiling eBPF program..."
	clang -O2 -target bpf -c $< -o $@
	@echo "eBPF program compiled: $@"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	rm -f $(EBPF_OBJ)
	@echo "Clean complete"

install: all
	@echo "Installing DDoS Protection System..."
	./scripts/install.sh
	@echo "Installation complete"

uninstall:
	@echo "Uninstalling DDoS Protection System..."
	systemctl stop ddos-protect 2>/dev/null || true
	systemctl disable ddos-protect 2>/dev/null || true
	rm -f /etc/systemd/system/ddos-protect.service
	rm -f /usr/local/bin/ddos-protect
	rm -rf /etc/ddos-protect
	@echo "Uninstall complete"

# Run with valgrind for memory leak detection
valgrind: all
	valgrind --leak-check=full --show-leak-kinds=all \
		--track-origins=yes --verbose \
		./$(TARGET) config/default.conf

# Performance profiling
profile: CFLAGS += -pg
profile: all

# Static analysis
analyze:
	cppcheck --enable=all --inconclusive $(SRC_DIR)

# Generate dependency files
depend:
	$(CC) -MM $(CFLAGS) -I$(INC_DIR) $(ALL_SRC) > .depend

# Help
help:
	@echo "DDoS Protection System - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the project (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install system-wide"
	@echo "  uninstall - Remove system installation"
	@echo "  valgrind  - Run with Valgrind memory checker"
	@echo "  profile   - Build with profiling enabled"
	@echo "  analyze   - Run static code analysis"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Build options:"
	@echo "  DEBUG=1   - Build with debug symbols and sanitizers"
	@echo ""
	@echo "Example:"
	@echo "  make              # Normal build"
	@echo "  make DEBUG=1      # Debug build"
	@echo "  sudo make install # Install"

-include .depend
