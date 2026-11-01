CC ?= cc
PKG_CONFIG ?= pkg-config

CPPFLAGS := -Iinclude $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
BASE_CFLAGS := -std=c17 -O2 -g -Wall -Wextra -Wpedantic -Werror \
	-Wconversion -Wshadow -Wformat=2 -Wstrict-prototypes \
	-fstack-protector-strong -D_FORTIFY_SOURCE=3
CFLAGS ?= $(BASE_CFLAGS)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo -lcrypto)
NFQ_CFLAGS_RAW := $(shell $(PKG_CONFIG) --cflags libnetfilter_queue 2>/dev/null)
# Treat third-party headers as system headers so their implementation-specific
# enum constants do not fail this project's strict -Wpedantic -Werror build.
NFQ_INCLUDE_DIRS := $(patsubst -I%,%,$(filter -I%,$(NFQ_CFLAGS_RAW)))
NFQ_CFLAGS := $(addprefix -isystem ,$(NFQ_INCLUDE_DIRS)) \
	$(filter-out -I%,$(NFQ_CFLAGS_RAW))
NFQ_LIBS := $(shell $(PKG_CONFIG) --libs libnetfilter_queue 2>/dev/null)

CORE_SRC := src/common.c src/config.c src/crypto.c src/handshake.c src/packet.c
DAEMON_SRC := $(CORE_SRC) src/nfqueue.c src/main.c
TEST_SRC := $(CORE_SRC) tests/test_runner.c

.PHONY: all clean test sanitize syntax-daemon smoke check-deps check-scripts install uninstall package

all: check-deps bin/sicd

check-deps:
	@$(PKG_CONFIG) --exists openssl || { echo "Missing OpenSSL development files (libssl-dev)."; exit 1; }
	@$(PKG_CONFIG) --exists libnetfilter_queue || { echo "Missing libnetfilter_queue development files."; echo "Run: sudo ./scripts/install_deps.sh"; exit 1; }

bin/sicd: $(DAEMON_SRC) $(wildcard include/sic/*.h)
	@mkdir -p bin
	$(CC) $(CPPFLAGS) $(NFQ_CFLAGS) $(CFLAGS) $(DAEMON_SRC) -o $@ $(OPENSSL_LIBS) $(NFQ_LIBS)

bin/test_runner: $(TEST_SRC) $(wildcard include/sic/*.h)
	@mkdir -p bin
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SRC) -o $@ $(OPENSSL_LIBS) -pthread

test: bin/test_runner check-scripts
	./bin/test_runner

# Lets minimal CI containers type-check the daemon even when the real NFQUEUE
# development package is absent. Production builds always use the real header.
syntax-daemon:
	$(CC) -Itests/stubs $(CPPFLAGS) $(CFLAGS) -fsyntax-only src/nfqueue.c src/main.c

check-scripts:
	@for script in scripts/*.sh tests/*.sh; do bash -n "$$script"; done
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck scripts/*.sh tests/*.sh; else echo "shellcheck not installed; syntax checks passed"; fi

bin/test_runner-sanitize: $(TEST_SRC) $(wildcard include/sic/*.h)
	@mkdir -p bin
	$(CC) $(CPPFLAGS) -std=c17 -O1 -g -Wall -Wextra -Wpedantic \
		-Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
		$(TEST_SRC) -o $@ $(OPENSSL_LIBS) -pthread

sanitize: bin/test_runner-sanitize
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./bin/test_runner-sanitize

smoke: all
	./tests/test_daemon_handshake.sh

install: all
	install -D -m 0755 bin/sicd /usr/local/sbin/sicd
	install -D -m 0644 packaging/sicd@.service /etc/systemd/system/sicd@.service
	install -d -m 0750 /etc/secure-inline-channel
	@echo "Copy and edit configs/device1.conf or configs/device2.conf under /etc/secure-inline-channel/."

uninstall:
	rm -f /usr/local/sbin/sicd /etc/systemd/system/sicd@.service

package:
	./scripts/create_submission_zip.sh

clean:
	rm -rf bin build
