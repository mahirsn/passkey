#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
keytool -genkeypair -alias wifi -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
    -dname CN=passkey.wifi -validity 1 -storetype PKCS12 -keystore "$tmp/test.p12" \
    -storepass test-only -keypass test-only >/dev/null 2>&1
javac --release 17 -d "$tmp/classes" android/src/sn/mahir/passkey/WifiKeyManager.java checks/WifiKeyManagerTest.java
java -cp "$tmp/classes" sn.mahir.passkey.WifiKeyManagerTest "$tmp/test.p12"
