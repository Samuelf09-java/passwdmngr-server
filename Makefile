CC ?= gcc

CFLAGS = -Wall -Wextra -O2 -I./include
CFLAGS += $(shell pkg-config --cflags libcurl)

LDLIBS := -lsodium -lcrypto -lssl -lcurl

SERVER_SRCS := $(wildcard src/*.c)
SERVER_SRCS := $(filter-out src/client.c, $(SERVER_SRCS))
SERVER_OBJS := $(SERVER_SRCS:src/%.c=build/%.o)

TARGET ?= passwdmngrd

SERVER_THREADS_QUEUE ?= 4:128

NUM_THREADS := $(word 1,$(subst :, ,$(SERVER_THREADS_QUEUE)))
QUEUE_SIZE  := $(word 2,$(subst :, ,$(SERVER_THREADS_QUEUE)))

CFLAGS += -DNUM_THREADS=$(NUM_THREADS) -DQUEUE_SIZE=$(QUEUE_SIZE)

# set to 'true' to remove os/hardware details from server info line
NO_DETAILED_SERVER_INFO ?= false

ifeq ($(NO_DETAILED_SERVER_INFO),true)
	CFLAGS += -DNO_DETAILED_SERVER_INFO
endif

ifneq ($(PORT),)
    CFLAGS += -DPORT=$(PORT)
endif

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

client: build/client.o build/cJSON.o
	@echo "Linking object files into executable 'client'"
	@$(CC) build/client.o build/cJSON.o -o client $(LDLIBS)
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
SMTP_FILE := smtp.conf


install: $(TARGET)
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: make install must be run as root"; \
		exit 1; \
	fi

	@mkdir -p /etc/passwdmngrd

	@if [ ! -f /etc/passwdmngrd/ca.key ]; then \
		echo "Creating CA..."; \
		openssl genrsa -out /etc/passwdmngrd/ca.key 4096; \
		openssl req -x509 -new -nodes -key /etc/passwdmngrd/ca.key \
			-sha256 -days 3650 \
			-out /etc/passwdmngrd/ca.crt \
			-subj "/C=US/ST=./L=./O=passwdmngrd/OU=./CN=passwdmngr-server CA"; \
	fi

	@if [ ! -f /etc/passwdmngrd/server.key ]; then \
		echo "Creating server key..."; \
		openssl genrsa -out /etc/passwdmngrd/server.key 4096; \
	fi

	@echo "Creating CSR..."
	@openssl req -new \
		-key /etc/passwdmngrd/server.key \
		-out /etc/passwdmngrd/server.csr \
		-subj "/C=US/ST=./L=./O=passwdmngrd/OU=./CN=$$(hostname)"

	@echo "Signing CSR..."
	@openssl x509 -req \
		-in /etc/passwdmngrd/server.csr \
		-CA /etc/passwdmngrd/ca.crt \
		-CAkey /etc/passwdmngrd/ca.key \
		-CAcreateserial \
		-out /etc/passwdmngrd/server.crt \
		-days 365 \
		-sha256

	@echo "Installing $(TARGET) to $(BINDIR)"
	@install -d $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/$(TARGET)

	@echo "Creating persistent directories"
	@install -d -m 755 $(LIBDIR)
	@install -d -m 700 $(VAULTDIR)
	@install -m 644 packaging/$(SMTP_FILE) $(LIBDIR)/$(SMTP_FILE)

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

	@echo "Leaving TLS certificates in /etc/passwdmngrd."


	@echo "Uninstall complete"