CC ?= gcc

CFLAGS = -Wall -Wextra -O2 -I./include
# CFLAGS += $(shell pkg-config --cflags <libs>)

LDLIBS := -lsodium -lcrypto -lssl

SERVER_SRCS := $(wildcard src/*.c)
SERVER_SRCS := $(filter-out src/client.c, $(SERVER_SRCS))
SERVER_OBJS := $(SERVER_SRCS:src/%.c=build/%.o)

TARGET ?= passwdmngrd

all: $(TARGET)

# Compile server
build/%.o: src/%.c
	@mkdir -p $(dir $@)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Link
$(TARGET): $(SERVER_OBJS)
	@echo "Linking object files into executable '$(TARGET)'"
	@$(CC) $(SERVER_OBJS) -o $(TARGET) $(LDLIBS)

build/client.o: src/client.c
	@mkdir -p $(dir $@)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

client: build/client.o $(TARGET)
	@echo "Linking object files into executable 'client'"
	@$(CC) build/client.o -o client $(LDLIBS)
	@echo "Done"

clean:
	@echo "Deleting compiled files"
	@rm -rf build $(TARGET)

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
LIBDIR := /var/lib/passwdmngrd
VAULTDIR := $(LIBDIR)/vaults
SYSDDIR := /etc/systemd/system
SERVICE := passwdmngrd.service


install: $(TARGET)
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: make install must be run as root"; \
		exit 1; \
	fi

	@echo "Installing $(TARGET) to $(BINDIR)"
	@install -d $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/$(TARGET)

	@echo "Creating persistent directories"
	@install -d -m 755 $(LIBDIR)
	@install -d -m 700 $(VAULTDIR)

	@echo "Installing systemd service"
	@install -d $(SYSDDIR)
	@install -m 644 packaging/$(SERVICE) $(SYSDDIR)/$(SERVICE)

	@echo "Reloading systemd"
	@systemctl daemon-reload

	@echo "To auto-start service at boot, run 'sudo systemctl enable $(TARGET)'"

uninstall:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: make uninstall must be run as root"; \
		exit 1; \
	fi

	@echo "Stopping service if running"
	@-systemctl stop $(TARGET) 2>/dev/null || true
	@-systemctl disable $(TARGET) 2>/dev/null || true

	@echo "Removing binary"
	@rm -f $(BINDIR)/$(TARGET)

	@echo "Removing systemd service"
	@rm -f $(SYSDDIR)/$(SERVICE)
	@systemctl daemon-reload

	@echo "Removing persistent directories"
	@rm -rf $(LIBDIR)

	@echo "Uninstall complete"