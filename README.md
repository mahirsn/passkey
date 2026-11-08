# Passkey

Your Android phone's fingerprint as a security key on Linux: login, lock
screen, `sudo`, polkit prompts and browser passkeys, over USB, Wi-Fi or Bluetooth.
Your password keeps working either way.

## Install

<a href="https://play.google.com/store/apps/details?id=sn.mahir.passkey"><img alt="Get it on Google Play" src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" height="80"></a>

On the phone: install the Passkey app and open it once. Pair it with the
computer for Bluetooth, or turn on USB debugging for USB. Set the app's
battery use to Unrestricted, or the phone may stop it in the background.

On the computer (Arch):

```
git clone https://github.com/mahirsn/passkey
cd passkey/pc
makepkg -si
passkey add
```

Other distributions: with Rust (cargo) installed, `make && sudo make install`.

`passkey add` sets up the service and PAM, then registers the device. It
checks your system first and names any missing package (pam-u2f, libfido2;
`adb` for USB, BlueZ for Bluetooth); it never installs packages itself.

## Wi-Fi

Turn on **Local Wi-Fi** in the app, then on the computer:

```
passkey wifi add <phone IP>    # paste the pairing code from the app
passkey add
```

Both devices must be on the same network. The phone's certificate is pinned
from the pairing code; profiles live in `/etc/passkey/wifi` (root only).

## Use

```
passkey status          what is connected and registered
passkey add [name]      register a device
passkey list            registered devices
passkey remove <n>      unregister a device
passkey uninstall       undo setup
```

With several devices connected, every one of them is asked and the first
answer counts. A device connected several ways uses USB, then Wi-Fi, then
Bluetooth.

## Layout

`src/` holds the Rust `passkey` executable (`passkey daemon` is the system
service), `pam/` holds the PAM module, and `pc/` holds Arch packaging.
`android/` holds the app; `android/build.sh` builds it without Gradle.
