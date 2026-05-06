CC       = gcc
CFLAGS   = -Wall -Wextra -std=c99 -D_XOPEN_SOURCE=700 -I./include
LDFLAGS  = -lpthread
FIXED_LDFLAGS = -lpthread -lssl -lcrypto
BUILD_DIR = build

# Platform detection for OpenSSL paths
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS with Homebrew OpenSSL
    BREW_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
    ifneq ($(BREW_PREFIX),)
        CFLAGS += -I$(BREW_PREFIX)/include
        FIXED_LDFLAGS += -L$(BREW_PREFIX)/lib
    endif
endif
ifeq ($(UNAME_S),Linux)
    # Linux (Docker / CI) — OpenSSL installed system-wide via apt
endif

VULN_SRCS = src/main.c src/network.c src/auth.c src/session.c \
            src/file_handler.c src/protocol.c src/config.c src/logger.c \
            src/backup_compress.c
VULN_OBJS = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(VULN_SRCS))

FIXED_SRCS = src/main.c src/network.c src/auth.c src/session.c \
             src/file_handler.c src/protocol.c src/config.c src/logger.c \
             src/backup_compress.c
FIXED_OBJS = $(patsubst src/%.c,$(BUILD_DIR)/%_fixed.o,$(FIXED_SRCS))

VULN_DEMOS = $(wildcard vulnerable/*.c)
FIXED_DEMOS = $(wildcard fixed/*.c)
VULN_DEMO_BINS = $(patsubst vulnerable/%.c,$(BUILD_DIR)/vuln_%,$(VULN_DEMOS))
FIXED_DEMO_BINS = $(patsubst fixed/%.c,$(BUILD_DIR)/fixed_%,$(FIXED_DEMOS))

# Fixed demos that need OpenSSL
FIXED_SSL_DEMOS = fixed/10_hardcoded_key_fixed.c
FIXED_SSL_BINS   = $(patsubst fixed/%.c,$(BUILD_DIR)/fixed_%,$(FIXED_SSL_DEMOS))

TEST_SRCS = $(wildcard tests/*.c)
TEST_BINS = $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))

.PHONY: all vulnerable fixed vuln-demos fixed-demos test clean

all: vulnerable

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ── Vulnerable build ────────────────────────────────────────────────

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVULNERABLE -c $< -o $@

vulnerable: $(VULN_OBJS)
	$(CC) -o $(BUILD_DIR)/securefile_server $(VULN_OBJS) $(LDFLAGS)

# ── Fixed build ─────────────────────────────────────────────────────

$(BUILD_DIR)/%_fixed.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DFIXED -c $< -o $@

fixed: $(FIXED_OBJS)
	$(CC) -o $(BUILD_DIR)/securefile_server_fixed $(FIXED_OBJS) $(FIXED_LDFLAGS)

# ── Vulnerability demos (standalone) ─────────────────────────────────

$(BUILD_DIR)/vuln_%: vulnerable/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

vuln-demos: $(VULN_DEMO_BINS)

# ── Fixed demos (standalone) ────────────────────────────────────────

$(BUILD_DIR)/fixed_%: fixed/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(FIXED_LDFLAGS)

fixed-demos: $(FIXED_DEMO_BINS)

# ── Tests ───────────────────────────────────────────────────────────

$(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DFIXED $< -o $@ $(FIXED_LDFLAGS)

test: fixed $(TEST_BINS)
	./scripts/run_tests.sh

# ── Docker ──────────────────────────────────────────────────────────

docker-build:
	docker compose -f docker/docker-compose.yml build

docker-run-vuln:
	docker compose -f docker/docker-compose.yml up dev

docker-run-fixed:
	docker compose -f docker/docker-compose.yml up dev-fixed

docker-test:
	docker compose -f docker/docker-compose.yml up test

docker-valgrind:
	docker compose -f docker/docker-compose.yml up valgrind

# ── CodeQL (local) ──────────────────────────────────────────────────

scan:
	codeql database create codeql-db --language=cpp --command="make fixed"
	codeql database analyze codeql-db --format=sarif-latest --output=codeql-results.sarif

clean:
	rm -rf $(BUILD_DIR) codeql-db/ codeql-results.sarif
