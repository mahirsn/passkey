# Passkey

Your Android phone's fingerprint as a security key on Linux: login, lock
screen, `sudo`, polkit prompts and browser passkeys, over USB or Bluetooth.
Your password keeps working either way.

## Install

On the phone: install the Passkey app and open it once. Pair it with the
computer for Bluetooth, or turn on USB debugging for USB.

On the computer (Arch):

```
git clone https://github.com/mahirsn/passkey
cd passkey/pc
makepkg -si
passkey setup
```

Other distributions: `make && sudo make install` instead of `makepkg -si`.

`passkey setup` checks your system and tells you what is missing; it never
installs packages itself. You need pam-u2f, libfido2, python3 and systemd,
plus `adb` for USB or BlueZ with python-dbus and python-gobject for Bluetooth.

## Use

```
passkey status          what is connected and registered
passkey add [name]      register a device
passkey list            registered devices
passkey remove <n>      unregister a device
passkey uninstall       undo setup
```

With several devices connected, every one of them is asked and the first
answer counts. A device on both USB and Bluetooth uses USB.

## Layout

`pc/` holds the daemon, the `passkey` command and the PAM module.
`android/` holds the app; `android/build.sh` builds it without Gradle.
