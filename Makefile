# make                  build (Rust workspace: passkey and pam_passkey.so)
# make install          PREFIX=/usr/local, DESTDIR for staging
# make uninstall        remove the installed files
# make android          the app (android/build.sh, SDK only, no Gradle)
# Then, as your user: passkey add
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
UNITDIR ?= $(PREFIX)/lib/systemd/system
# PAM loads modules only from its own directory, whatever the prefix.
PAMDIR  ?= $(patsubst %/,%,$(dir $(firstword $(wildcard \
	/usr/lib/security/pam_unix.so /usr/lib64/security/pam_unix.so /lib/security/pam_unix.so \
	/usr/lib/*-linux-gnu/security/pam_unix.so /lib/*-linux-gnu/security/pam_unix.so))))
CARGO   ?= cargo
CARGO_FLAGS ?= --locked
export CARGO_TARGET_DIR ?= target
# The PAM module runs this program; cargo rebuilds when it changes.
export PASSKEY_BIN = $(BINDIR)/passkey
R := $(CARGO_TARGET_DIR)/release

.PHONY: all pc android test install uninstall clean
all: pc

ifeq ($(PAMDIR)$(filter clean android,$(MAKECMDGOALS)),)
$(error PAM module directory not found (no pam_unix.so); pass PAMDIR=...)
endif

pc:
	$(CARGO) build --workspace --release $(CARGO_FLAGS)
	sed 's|@BINDIR@|$(BINDIR)|g' pc/passkeyd.service > $(R)/passkeyd.service

android:
	android/build.sh

test:
	$(CARGO) test --workspace $(CARGO_FLAGS)

install: pc
	install -Dm755 $(R)/passkey "$(DESTDIR)$(BINDIR)/passkey"
	install -Dm755 $(R)/libpam_passkey.so "$(DESTDIR)$(PAMDIR)/pam_passkey.so"
	install -Dm644 $(R)/passkeyd.service "$(DESTDIR)$(UNITDIR)/passkeyd.service"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/passkey" "$(DESTDIR)$(PAMDIR)/pam_passkey.so" "$(DESTDIR)$(UNITDIR)/passkeyd.service"

clean:
	$(CARGO) clean
	rm -rf android/out
