# Passkey

Use your Android device's fingerprint as a security key on Linux:
login, lock screen, `sudo`, system prompts and browser passkeys. Connects
over USB or Bluetooth.

## Setup

1. Install the Passkey app on your Android device and open it once.
   - For Bluetooth: pair the device with the computer.
   - For USB: turn on USB debugging and install `adb` on the computer.
2. On the computer, install the files, then configure as your user.
   On Arch:
   ```
   git clone https://github.com/mahirsn/passkey
   cd passkey/pc
   makepkg -si
   passkey setup
   ```
   Elsewhere, replace `makepkg -si` with `make && sudo make install`.
   `passkey setup` checks the system first and names any missing package;
   it installs none itself. Confirm with your fingerprint when asked.

   Needed: pam-u2f (with `pamu2fcfg`), libfido2 tools (`fido2-token`),
   python3, a kernel with uhid, systemd (without it, setup says how to start
   the daemon yourself). For USB: `adb`. For Bluetooth: BlueZ and Python
   D-Bus/GObject bindings. To build: a C compiler and PAM headers.

   Coming from the earlier `pc/passkey setup` installer: before `makepkg -si`,
   run `sudo rm /usr/lib/security/pam_passkey.so` (pacman refuses to overwrite
   it); `passkey setup` then clears the rest of the old files.

## Layout

```
pc/        computer side: passkeyd (daemon), passkey (CLI), PAM module
           Makefile (PREFIX, DESTDIR), PKGBUILD
android/   the app; android/build.sh builds it from the SDK, no Gradle
Makefile   make (pc), make android, make install
```

## Commands

```
passkey status             # what is connected and registered
passkey add [name]         # register another device (asks which, if several are connected)
passkey list               # registered devices
passkey remove <n|name>    # unregister a device
passkey uninstall          # undo setup, registrations included
```

Removing: `sudo make uninstall` (or `pacman -R passkey`) runs
`passkey uninstall` first, then removes the files.
