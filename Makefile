# Rust computer side plus the unchanged SDK-only Android build.
PREFIX ?= /usr
DESTDIR ?=
PAMDIR ?= $(PREFIX)/lib/security
UNITDIR ?= $(PREFIX)/lib/systemd/system

.PHONY: all pc android test install clean
all: pc
pc:
	cargo build --workspace --release --locked
android:
	android/build.sh
test:
	cargo test --workspace --locked
install: pc
	install -Dm755 target/release/passkey "$(DESTDIR)$(PREFIX)/bin/passkey"
	install -Dm755 target/release/libpam_passkey.so "$(DESTDIR)$(PAMDIR)/pam_passkey.so"
	install -Dm644 pc/passkeyd.service "$(DESTDIR)$(UNITDIR)/passkeyd.service"
clean:
	cargo clean
	rm -rf android/out
