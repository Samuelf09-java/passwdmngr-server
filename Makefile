CC ?= gcc

CFLAGS = -Wall -Wextra -O2 -I./include
# CFLAGS += $(shell pkg-config --cflags <libs>)

LDLIBS := -lsodium -lcrypto -lssl

TARGET ?= passwdmngr-server

all: $(TARGET)

# Compile server
build/server.o: src/server.c
	@mkdir -p $(dir $@)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Link
$(TARGET): build/server.o
	@echo "Linking object files into executable '$(TARGET)'"
	@$(CC) build/server.o -o $(TARGET) $(LDLIBS)
	@echo "Done"

build/client.o: src/client.c
	@mkdir -p $(dir $@)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

client: build/client.o $(TARGET)
	@echo "Linking object files into executable 'client'"
	@$(CC) build/server.o -o client $(LDLIBS)
	@echo "Done"

clean:
	@echo "Deleting compiled files"
	@rm -rf build $(TARGET)
