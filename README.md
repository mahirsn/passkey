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
passkey add
```

Other distributions: install Rust, pam-u2f, libfido2 and systemd, then run
`make && sudo make install`. USB additionally needs `adb`; Bluetooth needs
BlueZ. `passkey add` configures the service and PAM before registering the
device.

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

`src/` holds the Rust `passkey` executable (`passkey daemon` is the system
service), `pam/` holds the PAM module, and `pc/` holds Arch packaging.
`android/` holds the unchanged app; `android/build.sh` builds it without
Gradle.
