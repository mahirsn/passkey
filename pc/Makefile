# make                        build into build/
# make install                PREFIX=/usr/local, DESTDIR for staging
# make uninstall              runs `passkey uninstall`, then removes the files
# Then, as your user: passkey setup
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
LIBDIR  ?= $(PREFIX)/lib/passkey
UNITDIR ?= $(PREFIX)/lib/systemd/system
# PAM loads modules only from its own directory, whatever the prefix.
PAMDIR  ?= $(patsubst %/,%,$(dir $(firstword $(wildcard \
	/usr/lib/security/pam_unix.so /usr/lib64/security/pam_unix.so /lib/security/pam_unix.so \
	/usr/lib/*-linux-gnu/security/pam_unix.so /lib/*-linux-gnu/security/pam_unix.so))))
BUILDDIR ?= build
CFLAGS  ?= -O2 -Wall

B := $(BUILDDIR)
OUT := $(B)/pam_passkey.so $(B)/passkey-u2f $(B)/passkey $(B)/passkeyd.service
SUBST = sed -e 's|@LIBDIR@|$(LIBDIR)|g' -e 's|@PAMDIR@|$(PAMDIR)|g'

.PHONY: all install uninstall clean FORCE
all: $(OUT)

ifeq ($(PAMDIR)$(filter clean,$(MAKECMDGOALS)),)
$(error PAM module directory not found (no pam_unix.so); pass PAMDIR=...)
endif

# Rebuilds everything when the paths baked into it change.
$(B)/paths: FORCE
	@mkdir -p $(B)
	@echo '$(LIBDIR) $(PAMDIR)' | cmp -s - $@ || echo '$(LIBDIR) $(PAMDIR)' > $@

$(B)/pam_passkey.so: pam_passkey.c $(B)/paths
	$(CC) $(CPPFLAGS) $(CFLAGS) -DHELPER='"$(LIBDIR)/passkey-u2f"' -shared -fPIC $(LDFLAGS) -o $@ $< -lpam

$(B)/passkey-u2f: passkey-u2f.c
	@mkdir -p $(B)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpam

$(B)/passkey $(B)/passkeyd.service: $(B)/%: % $(B)/paths
	$(SUBST) $< > $@

install: all
	install -Dm755 $(B)/passkey "$(DESTDIR)$(BINDIR)/passkey"
	install -Dm755 passkeyd "$(DESTDIR)$(LIBDIR)/passkeyd"
	install -Dm755 $(B)/passkey-u2f "$(DESTDIR)$(LIBDIR)/passkey-u2f"
	install -Dm755 $(B)/pam_passkey.so "$(DESTDIR)$(PAMDIR)/pam_passkey.so"
	install -Dm644 $(B)/passkeyd.service "$(DESTDIR)$(UNITDIR)/passkeyd.service"

uninstall:
	if [ -z "$(DESTDIR)" ] && [ -x "$(BINDIR)/passkey" ]; then "$(BINDIR)/passkey" uninstall; fi
	rm -f "$(DESTDIR)$(BINDIR)/passkey" "$(DESTDIR)$(PAMDIR)/pam_passkey.so" "$(DESTDIR)$(UNITDIR)/passkeyd.service"
	rm -rf "$(DESTDIR)$(LIBDIR)"

clean:
	rm -rf $(B)
