# Passkey

Your Android phone's fingerprint as a security key on Linux: login, lock
screen, `sudo`, polkit prompts and browser passkeys, over USB, direct local Wi-Fi or Bluetooth.
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

## Direct local Wi-Fi (no USB debugging)

This checkout adds a native TLS transport on the phone. The Play Store app does
not contain this change: build/install the modified Android app first. It needs
Android 11 or newer. Enable **Local Wi-Fi** in the app, keep both devices on the
same Wi-Fi, and note the phone's displayed IP address (TCP port **40719**).

On the computer, after installing this checkout's companion:

```
passkey wifi add 192.168.1.50
# When asked, paste the code from the phone's "Copy pairing code" button.
passkey add
passkey status
```

Pairing and FIDO registration are separate: `wifi add` authorizes the encrypted
connection; `passkey add` registers the phone's fingerprint-protected credential
and configures the service/PAM as before. A running daemon picks up saved Wi-Fi
profiles automatically. It reconnects while the phone's Wi-Fi listener is enabled.
Bluetooth permissions, USB debugging and adb are not needed for this path.

```
passkey wifi list
passkey wifi remove 192.168.1.50
```

The app's **Forget all Wi-Fi computers** button disconnects Wi-Fi clients and
rotates its pairing secret. To change the phone's IP, run `wifi add` with its new
address and the same code. A DHCP reservation avoids needing to do this. There
is no cloud service or automatic LAN discovery. Guest Wi-Fi/client isolation or
firewall rules may block phone-to-computer connections. The phone listens only
for connections arriving on its Wi-Fi IPv4 interface, never mobile data/VPN.
Keep battery use **Unrestricted** so Android does not suspend the connection.

TLS verifies the phone's exact certificate SHA-256 fingerprint from the copied
pairing code **before** transmitting the random 256-bit authentication secret.
Unauthenticated connections cannot send CTAP requests or display fingerprint
prompts. Computer profiles live in `/etc/passkey/wifi` (directory 0700, files
0600, owned by root). Treat the pairing code like a password; do not put it in
shell arguments/history or share it. Existing USB and Bluetooth transports use
their previous wire protocol. Wi-Fi has its own stable device identity; prefer
one transport per phone during registration to avoid showing it twice.

The Wi-Fi build can be installed alongside the Play version, without deleting
its existing credentials:

```sh
ANDROID_HOME=/path/to/android-sdk \
PASSKEY_PACKAGE=sn.mahir.passkey.wifi \
PASSKEY_KEYSTORE="$PWD/store/wifi-upload.jks" \
PASSKEY_KEYPASS="$PWD/store/wifi-upload.jks.pass" android/build.sh
```

Keep that signing key to update the same APK later. A differently signed APK
cannot update the Play app; **do not uninstall that app to work around this**,
as uninstalling deletes its credentials. The separate Wi-Fi app needs its own
`passkey add` registration. Builds need JDK 17+, SDK platform 36 and build-tools
36.0.0; the computer needs OpenSSL development files to compile (`openssl` on
Arch, `libssl-dev` on Debian/Ubuntu). No installed PAM configuration or phone
credentials are changed by building. Wi-Fi tests use a local TLS peer; physical
phone/login/lock-screen behavior still needs a device test.

## Use

```
passkey status          what is connected and registered
passkey add [name]      register a device
passkey list            registered devices
passkey remove <n>      unregister a device
passkey uninstall       undo setup
```

With several devices connected, every one of them is asked and the first
answer counts. A device on both USB and Bluetooth uses USB. The native Wi-Fi
identity is separate from the legacy USB/Bluetooth identity.

## Layout

`src/` holds the Rust `passkey` executable (`passkey daemon` is the system
service), `pam/` holds the PAM module, and `pc/` holds Arch packaging.
`android/` holds the Android app and native Wi-Fi listener; `android/build.sh` builds it without
Gradle.
