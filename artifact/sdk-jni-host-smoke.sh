#!/bin/sh
# Actual host-JVM JNI consumer. No emulator or physical Android evidence implied.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
: "${JAVA_HOME:?Select JDK 25 for the host JNI check}"
test -x "$JAVA_HOME/bin/java"
test -x "$JAVA_HOME/bin/javac"
mkdir -p target
WORK=$(mktemp -d "$ROOT/target/sdk-jni-host.XXXXXX")
mkdir -p "$WORK/classes" "$WORK/lib"
case "$(uname -s)" in
    Darwin) JNI_PLATFORM=darwin; LIB_SUFFIX=dylib; LINK_FLAG=-dynamiclib ;;
    Linux) JNI_PLATFORM=linux; LIB_SUFFIX=so; LINK_FLAG=-shared ;;
    *) printf 'error: host JNI smoke requires macOS or Linux\n' >&2; exit 1 ;;
esac
test -f "$ROOT/target/release/libq_periapt_ffi_abi2.$LIB_SUFFIX"
cc -std=c11 -Wall -Wextra -Werror -fPIC -fvisibility=hidden "$LINK_FLAG" \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/$JNI_PLATFORM" \
    -Icrates/q-periapt-ffi/include bindings/android/jni/qperiapt_jni.c \
    -Ltarget/release -lq_periapt_ffi_abi2 -Wl,-rpath,"$ROOT/target/release" \
    -o "$WORK/lib/libqperiapt_jni_abi2.$LIB_SUFFIX"
"$JAVA_HOME/bin/javac" --release 11 -Xlint:all -Werror -d "$WORK/classes" \
    bindings/android/src/main/java/dev/qperiapt/android/*.java \
    bindings/android/src/test/java/dev/qperiapt/android/QPeriaptSDKTest.java
"$JAVA_HOME/bin/java" --enable-native-access=ALL-UNNAMED -Xcheck:jni \
    -Djava.library.path="$WORK/lib:$ROOT/target/release" -cp "$WORK/classes" \
    dev.qperiapt.android.QPeriaptSDKTest "$ROOT/bindings/signed-policy-vectors.json"
printf 'SDK_JNI_HOST_ARTIFACTS=%s\n' "$WORK"
