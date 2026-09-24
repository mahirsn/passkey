#!/bin/bash
# Builds without Gradle, from the SDK platform and build-tools only; nothing is downloaded.
#   ./build.sh                      out/passkey.apk (signed) and out/passkey.aab (for Play)
#   PASSKEY_AUTO_APPROVE=1 ./build.sh   test build, package sn.mahir.passkey.test, approves
#                                   without asking. For automated tests only.
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
JAR="$SDK/platforms/android-37.0/android.jar"
BT="$SDK/build-tools/36.0.0"
TARGET=36
MIN=30
KEY="${PASSKEY_KEYSTORE:-$HOME/.config/env/passkey-upload.jks}"
PASS_FILE="${PASSKEY_KEYPASS:-$HOME/.config/env/passkey-upload.jks.pass}"
# bundletool and its dependencies from the Gradle cache (any past Android Studio build leaves them).
G="$HOME/.gradle/caches/modules-2/files-2.1"
BUNDLETOOL_CP="${BUNDLETOOL_CP:-$(find "$G"/{com.android.tools.build,com.google.guava,com.google.protobuf,com.google.dagger,javax.inject,org.bitbucket.b_c,org.slf4j,com.google.errorprone,com.google.auto.value,org.checkerframework} \
    -name '*.jar' ! -name '*sources*' 2>/dev/null | grep -vE 'gradle-|aapt2-[0-9]|builder-|lint' | tr '\n' ':')}"
AUTO="${PASSKEY_AUTO_APPROVE:-0}"
quiet() { "$@" 2>&1 | grep -v '^WARNING' || true; }

rm -rf out && mkdir -p out/classes out/dex out/gen
cat > out/gen/Flags.java <<J
package sn.mahir.passkey;
final class Flags { static final boolean AUTO_APPROVE = $AUTO == 1; }
J
RENAME=()
[[ "$AUTO" == 1 ]] && RENAME=(--rename-manifest-package sn.mahir.passkey.test)

"$BT/aapt2" compile --dir res -o out/res.zip
link() {
    "$BT/aapt2" link "$@" --manifest AndroidManifest.xml -I "$JAR" out/res.zip \
        --min-sdk-version $MIN --target-sdk-version $TARGET --custom-package sn.mahir.passkey "${RENAME[@]}"
}
link -o out/unsigned.apk --java out/gen
javac -encoding UTF-8 --release 17 -nowarn -classpath "$JAR" -d out/classes $(find src out/gen -name '*.java')
"$BT/d8" --min-api $MIN --lib "$JAR" --output out/dex $(find out/classes -name '*.class')
(cd out/dex && zip -q ../unsigned.apk classes.dex)
"$BT/zipalign" -f 4 out/unsigned.apk out/aligned.apk

if [[ ! -f "$KEY" ]]; then
    install -d -m 700 "$(dirname "$KEY")"
    head -c 24 /dev/urandom | base64 > "$PASS_FILE"; chmod 600 "$PASS_FILE"
    keytool -genkeypair -keystore "$KEY" -storepass:file "$PASS_FILE" -keypass:file "$PASS_FILE" \
        -alias upload -keyalg RSA -keysize 4096 -validity 36500 -dname "CN=Passkey" >/dev/null 2>&1
    chmod 600 "$KEY"
fi
quiet "$BT/apksigner" sign --ks "$KEY" --ks-pass "file:$PASS_FILE" --ks-key-alias upload \
    --out out/passkey.apk out/aligned.apk
echo "out/passkey.apk"

# Play wants an app bundle: the same app linked in protobuf form, laid out as a module.
if [[ "$AUTO" != 1 && "$BUNDLETOOL_CP" == *bundletool* ]]; then
    link --proto-format -o out/proto.apk
    rm -rf out/base && mkdir -p out/base/manifest out/base/dex
    (cd out/base && unzip -q ../proto.apk && mv AndroidManifest.xml manifest/)
    cp out/dex/classes.dex out/base/dex/
    (cd out/base && zip -qr ../base.zip .)
    quiet java -cp "$BUNDLETOOL_CP" com.android.tools.build.bundletool.BundleToolMain \
        build-bundle --modules=out/base.zip --output=out/passkey.aab
    jarsigner -keystore "$KEY" -storepass:file "$PASS_FILE" -keypass:file "$PASS_FILE" \
        -sigalg SHA256withRSA -digestalg SHA-256 out/passkey.aab upload >/dev/null
    echo "out/passkey.aab"
fi
