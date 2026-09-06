"""Execute the real result writer against file I/O; this is not an ART/JNI test."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

ACTIVITY = r"""
package android.app;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
public class Activity {
    public static final int MODE_PRIVATE = 0;
    public final List<String> closed = new ArrayList<String>();
    public String fail = "";
    private final File directory;
    public Activity(File directory) { this.directory = directory; }
    public File getFilesDir() { return directory; }
    public FileOutputStream openFileOutput(String name, int mode) throws IOException {
        if (mode != MODE_PRIVATE) throw new AssertionError("wrong mode");
        return new FileOutputStream(new File(directory, name)) {
            @Override public void write(byte[] data) throws IOException {
                if (fail.equals("json-write") && name.endsWith(".json")) throw new IOException("write failed");
                super.write(data);
            }
            @Override public void close() throws IOException {
                super.close();
                if (new File(directory, "qperiapt-android-device-result.txt").exists()) throw new AssertionError("marker visible before file close");
                if (name.endsWith(".pending")) {
                    String json = Files.readString(new File(directory, "qperiapt-android-device-result.json").toPath(), StandardCharsets.UTF_8);
                    if (!json.endsWith("\n}\n")) throw new AssertionError("JSON incomplete before marker close");
                    if (fail.equals("marker-close")) throw new IOException("close failed");
                    if (fail.equals("rename")) Files.createDirectory(new File(directory, "qperiapt-android-device-result.txt").toPath());
                }
                closed.add(name);
            }
        };
    }
}
"""
HARNESS = r"""
package dev.qperiapt.androidsmoke;
import android.app.Activity;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
public final class ResultWriterHarness {
    private static final String ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public static void main(String[] arguments) throws Exception {
        Path base = Path.of(arguments[0]);
        Path success = Files.createDirectory(base.resolve("success"));
        Activity activity = new Activity(success.toFile());
        QPeriaptSmokeResults.write(activity, ID, true, Arrays.asList("runtimeVersionOnly"), null);
        String marker = Files.readString(success.resolve("qperiapt-android-device-result.txt"));
        if (!marker.equals("QPERIAPT_ANDROID_DEVICE_PASS run-id=" + ID + " tests=1\n")) throw new AssertionError("marker bytes changed");
        String expected = "{\n  \"schema\": 1,\n  \"status\": \"pass\",\n  \"run_id\": \"" + ID
            + "\",\n  \"test_count\": 1,\n  \"passed_tests\": [\"runtimeVersionOnly\"]\n}\n";
        byte[] committed = Files.readAllBytes(success.resolve("qperiapt-android-device-result.json"));
        if (!new String(committed, StandardCharsets.UTF_8).equals(expected)) throw new AssertionError("JSON bytes changed");
        if (!activity.closed.equals(Arrays.asList("qperiapt-android-device-result.json", "qperiapt-android-device-result.txt.pending"))) throw new AssertionError("close/commit order changed");
        if (Files.exists(success.resolve("qperiapt-android-device-result.txt.pending"))) throw new AssertionError("pending marker retained after rename");
        try {
            QPeriaptSmokeResults.write(activity, ID, false, Arrays.asList("runtimeVersionOnly"), new IOException("later"));
            throw new AssertionError("committed result was overwritten");
        } catch (IOException expectedFailure) {
            if (!Arrays.equals(committed, Files.readAllBytes(success.resolve("qperiapt-android-device-result.json")))) throw new AssertionError("completed JSON changed");
        }
        for (String failure : Arrays.asList("json-write", "marker-close", "rename")) {
            Path directory = Files.createDirectory(base.resolve(failure));
            Activity failing = new Activity(directory.toFile()); failing.fail = failure;
            try {
                QPeriaptSmokeResults.write(failing, ID, true, Arrays.asList("runtimeVersionOnly"), null);
                throw new AssertionError("I/O failure was swallowed");
            } catch (IOException expectedFailure) {
                if (Files.isRegularFile(directory.resolve("qperiapt-android-device-result.txt"))) throw new AssertionError("failed writer exposed completed marker");
            }
        }
        System.out.println("RESULT_WRITER_IO_PASS");
    }
}
"""


class AndroidSmokeResultWriterTests(unittest.TestCase):
    def test_actual_writer_commits_json_then_closed_marker_and_propagates_io_failures(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="qperiapt-result-writer-") as temporary:
            root = pathlib.Path(temporary)
            activity = root / "android/app/Activity.java"
            activity.parent.mkdir(parents=True)
            activity.write_text(ACTIVITY)
            harness = root / "dev/qperiapt/androidsmoke/ResultWriterHarness.java"
            harness.parent.mkdir(parents=True)
            harness.write_text(HARNESS)
            writer = (
                ROOT
                / "bindings/android/smoke/common/dev/qperiapt/androidsmoke/QPeriaptSmokeResults.java"
            )
            classes = root / "classes"
            result = subprocess.run(
                [
                    "javac",
                    "--release",
                    "11",
                    "-Xlint:all",
                    "-Werror",
                    "-d",
                    str(classes),
                    str(activity),
                    str(harness),
                    str(writer),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                (result.returncode, result.stdout, result.stderr), (0, "", "")
            )
            data = root / "results"
            data.mkdir()
            result = subprocess.run(
                [
                    "java",
                    "-cp",
                    str(classes),
                    "dev.qperiapt.androidsmoke.ResultWriterHarness",
                    str(data),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                (result.returncode, result.stdout, result.stderr),
                (0, "RESULT_WRITER_IO_PASS\n", ""),
            )


if __name__ == "__main__":
    unittest.main()
