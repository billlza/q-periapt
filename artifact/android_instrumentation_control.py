#!/usr/bin/env python3
"""Cold-image framework instrumentation control, with no SDK or native library.

This diagnostic is deliberately separate from SDK qualification. Three recorded
invocations are distinct observations, never retries that hide an earlier failure.
"""
from __future__ import annotations

import re
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from android_runtime_control import Control, file_hash, run_control

PACKAGE = "org.qperiapt.runtimecontrol"
COMPONENT = PACKAGE + "/.ControlRunner"
JAVA = """package org.qperiapt.runtimecontrol;
import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

public final class ControlRunner extends Instrumentation {
    private String token;
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        token = arguments == null ? null : arguments.getString("control_token");
        if (token == null || !token.matches("[0-9a-f]{32}")) {
            finish(Activity.RESULT_CANCELED, new Bundle());
            return;
        }
        start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        result.putString("qperiapt_control_token", token);
        result.putString("qperiapt_control_version", "1");
        finish(Activity.RESULT_OK, result);
    }
}
"""
MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.qperiapt.runtimecontrol" android:versionCode="1" android:versionName="1">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
    <application android:label="Framework runtime control" android:allowBackup="false" />
    <instrumentation android:name=".ControlRunner"
        android:targetPackage="org.qperiapt.runtimecontrol" android:functionalTest="true" />
</manifest>
"""


def invocation_passed(record: dict, raw: str, token: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("noncanonical control token")
    expected = {
        "INSTRUMENTATION_RESULT: qperiapt_control_token=" + token,
        "INSTRUMENTATION_RESULT: qperiapt_control_version=1",
        "INSTRUMENTATION_CODE: -1",
    }
    lines = raw.strip().splitlines()
    return (record["returncode"] == 0 and not record["timed_out"]
            and len(lines) == 3 and set(lines) == expected)


def system_crash_observed(raw: str) -> bool:
    return bool(re.search(r"FATAL EXCEPTION IN SYSTEM PROCESS|>>> system_server <<<|Fatal signal[^\n]*\(system_server\)", raw))


def check_apk(apk: Path, dex: Path) -> dict:
    # aapt2 contributes the manifest/resource table; D8 contributes our single Java class.
    # v1 signature metadata is optional, but any native/SDK/assets input is refused.
    allowed = {"AndroidManifest.xml", "resources.arsc", "classes.dex", "META-INF/MANIFEST.MF",
               "META-INF/CONTROL.SF", "META-INF/CONTROL.RSA"}
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not set(names) <= allowed:
            raise RuntimeError("control APK contains unexpected or duplicate entries")
        if not {"AndroidManifest.xml", "classes.dex"} <= set(names):
            raise RuntimeError("control APK is missing manifest or DEX")
        if archive.read("classes.dex") != dex.read_bytes():
            raise RuntimeError("control APK substituted the compiled DEX")
        return {"sha256": file_hash(apk), "bytes": apk.stat().st_size,
                "entries": sorted(names), "dex_sha256": file_hash(dex)}


def build_apk(control: Control) -> Path:
    build = control.work / "framework-build"
    build.mkdir()
    sources = control.output / "source"
    sources.mkdir()
    java = sources / "ControlRunner.java"
    manifest = sources / "AndroidManifest.xml"
    java.write_text(JAVA)
    manifest.write_text(MANIFEST)
    android = control.sdk / "platforms/android-35/android.jar"
    tools = control.sdk / "build-tools/36.0.0"
    classes, dex = build / "classes", build / "dex"
    classes.mkdir()
    dex.mkdir()
    javac, keytool = shutil.which("javac"), shutil.which("keytool")
    if javac is None or keytool is None:
        raise RuntimeError("Java compiler/keytool unavailable")
    control.text(control.command("javac-version", [javac, "-version"]))
    control.text(control.command("compile-control", [javac, "--release", "11", "-Xlint:all", "-Werror",
                 "-cp", str(android), "-d", str(classes), str(java)], 60))
    jar = build / "classes.jar"
    class_files = list(classes.rglob("*.class"))
    expected_class = classes / "org/qperiapt/runtimecontrol/ControlRunner.class"
    if class_files != [expected_class]:
        raise RuntimeError("control compiler emitted unexpected classes")
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(expected_class, "org/qperiapt/runtimecontrol/ControlRunner.class")
    control.text(control.command("dex-control", [str(tools / "d8"), "--min-api", "23",
                 "--lib", str(android), "--output", str(dex), str(jar)], 60))
    dex_file = dex / "classes.dex"
    dump = control.text(control.command("inspect-control-dex", [str(tools / "dexdump"), "-d", str(dex_file)]))
    descriptors = re.findall(r"Class descriptor\s*:\s*'([^']+)'", dump)
    if descriptors != ["Lorg/qperiapt/runtimecontrol/ControlRunner;"]:
        raise RuntimeError("control DEX contains unexpected classes")
    base = build / "manifest.apk"
    control.text(control.command("link-control", [str(tools / "aapt2"), "link", "--manifest", str(manifest),
                 "-I", str(android), "--min-sdk-version", "23", "--target-sdk-version", "35", "-o", str(base)], 60))
    unsigned = build / "unsigned.apk"
    with zipfile.ZipFile(base) as src, zipfile.ZipFile(unsigned, "w", compression=zipfile.ZIP_DEFLATED) as out:
        if sorted(src.namelist()) != ["AndroidManifest.xml", "resources.arsc"]:
            raise RuntimeError("unexpected control manifest APK entries")
        for name in src.namelist():
            out.writestr(name, src.read(name))
        out.write(dex_file, "classes.dex")
    aligned = build / "aligned.apk"
    control.text(control.command("align-control", [str(tools / "zipalign"), "-P", "16", "4", str(unsigned), str(aligned)]))
    keystore = build / "control.p12"
    # Disposable diagnostic signing identity; its private key is never uploaded.
    control.text(control.command("key-control", [keytool, "-genkeypair", "-storetype", "PKCS12",
                 "-keystore", str(keystore), "-storepass", "runtime-control", "-keypass", "runtime-control",
                 "-alias", "control", "-dname", "CN=Framework Runtime Control", "-keyalg", "RSA",
                 "-keysize", "2048", "-validity", "7", "-noprompt"], 30))
    apk = control.output / "framework-control.apk"
    control.text(control.command("sign-control", [str(tools / "apksigner"), "sign", "--ks", str(keystore),
                 "--ks-pass", "pass:runtime-control", "--key-pass", "pass:runtime-control",
                 "--ks-key-alias", "control", "--v1-signing-enabled", "true", "--out", str(apk), str(aligned)]))
    control.text(control.command("verify-control-signature", [str(tools / "apksigner"), "verify", "--verbose",
                 "--print-certs", str(apk)]))
    control.text(control.command("verify-control-alignment", [str(tools / "zipalign"), "-c", "-P", "16", "4", str(apk)]))
    info = check_apk(apk, dex_file)
    info.update(java_sha256=file_hash(java), manifest_sha256=file_hash(manifest),
                android_jar_sha256=file_hash(android), controller_sha256=file_hash(Path(__file__)),
                tools={name: file_hash(tools / name) for name in ("aapt2", "apksigner", "d8", "dexdump", "zipalign")},
                class_descriptors=descriptors, native_library_present=False)
    control.result["control_apk"] = info
    control.save()
    return apk


class InstrumentationControl(Control):
    def run(self):
        self.result.update(kind="qperiapt.android_framework_instrumentation_control",
                           scope="One pinned cold x86_64 ps16k emulator; pure Java framework Instrumentation, no SDK/native library. Not an SDK, AGP, physical-device or native-16K qualification.",
                           controller_sha256=file_hash(Path(__file__)),
                           common_controller_sha256=file_hash(Path(__file__).with_name("android_runtime_control.py")))
        # Build before boot, so compilation does not warm up the running guest.
        self.apk = build_apk(self)
        super().run()

    def observe(self):
        initial = self.text(self.adb_command("instrumentation-initial-pid", ["shell", "pidof", "system_server"]))
        if re.fullmatch(r"[1-9][0-9]*", initial) is None:
            raise RuntimeError("original system_server PID unavailable")
        self.result["initial_system_server_pid"] = initial
        self.snapshot("before-install")
        self.result["system_crash_observed"] = system_crash_observed(
            (self.output / "before-install-logcat.stdout").read_text())
        installed = self.text(self.adb_command("install-control", ["install", "--no-streaming", str(self.apk)], 60))
        if installed.splitlines()[-1:] != ["Success"]:
            raise RuntimeError("control APK installation not acknowledged")
        for index in range(3):
            label = f"invocation-{index:02}"
            token = uuid.uuid4().hex
            elapsed = time.monotonic() - self.result["boot_observed_monotonic"]
            record = self.adb_command(label, ["shell", "am", "instrument", "-w", "-r", "-e",
                                      "control_token", token, COMPONENT], 60)
            raw = (self.output / (label + ".stdout")).read_text()
            pid_record = self.adb_command(label + "-pid", ["shell", "pidof", "system_server"])
            pid_raw = (self.output / (pid_record["label"] + ".stdout")).read_text().strip()
            same_pid = (pid_record["returncode"] == 0 and not pid_record["timed_out"] and pid_raw == initial)
            self.samples.append({"sample": index, "invocation": label, "token": token,
                                 "seconds_after_boot_observed": elapsed,
                                 "framework_invocation_passed": invocation_passed(record, raw, token),
                                 "system_server_pid": pid_raw, "original_system_server": same_pid})
            self.save()
            self.snapshot(label + "-after")
            crash = system_crash_observed((self.output / (label + "-after-logcat.stdout")).read_text())
            self.samples[-1]["system_crash_observed"] = crash
            self.result["system_crash_observed"] |= crash
            self.save()
            if index < 2:
                time.sleep(5)
        self.result["completed"] = True
        self.result["observations_clean"] = (
            not self.result.get("diagnostic_failures") and not self.result["system_crash_observed"]
            and all(s["framework_invocation_passed"] and s["original_system_server"] for s in self.samples))
        # Never uninstall through a possibly changed package manager. The only guest
        # is this disposable owned emulator, whose process is stopped by the common owner.


def main() -> int:
    return run_control(InstrumentationControl, "android-instrumentation-control")


if __name__ == "__main__":
    raise SystemExit(main())
