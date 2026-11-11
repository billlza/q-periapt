package dev.qperiapt.androidsmoke;

import android.app.Activity;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Fixed run-bound result encoding; this class has no facade or JNI references. */
final class QPeriaptSmokeResults {
    private static final String RESULT_TXT = "qperiapt-android-device-result.txt";
    private static final String RESULT_JSON = "qperiapt-android-device-result.json";

    private QPeriaptSmokeResults() {
    }

    static void write(Activity activity, String runId, boolean ok, List<String> passed, Throwable failure) throws Exception {
        File completed = new File(activity.getFilesDir(), RESULT_TXT);
        if (completed.exists()) {
            throw new IOException("smoke result is already committed");
        }
        String marker = (ok ? "QPERIAPT_ANDROID_DEVICE_PASS" : "QPERIAPT_ANDROID_DEVICE_FAIL")
                + " run-id=" + runId + " tests=" + passed.size() + "\n";
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"schema\": 1,\n");
        json.append("  \"status\": \"").append(ok ? "pass" : "fail").append("\",\n");
        json.append("  \"run_id\": \"").append(escape(runId)).append("\",\n");
        json.append("  \"test_count\": ").append(passed.size()).append(",\n");
        json.append("  \"passed_tests\": [");
        for (int i = 0; i < passed.size(); i++) {
            if (i > 0) {
                json.append(", ");
            }
            json.append("\"").append(escape(passed.get(i))).append("\"");
        }
        json.append("]");
        if (failure != null) {
            json.append(",\n  \"failure\": \"").append(escape(failure.getClass().getName() + ": " + failure.getMessage())).append("\"");
        }
        json.append("\n}\n");
        FileOutputStream out = activity.openFileOutput(RESULT_JSON, Activity.MODE_PRIVATE);
        try {
            out.write(json.toString().getBytes(StandardCharsets.UTF_8));
        } finally {
            out.close();
        }
        // The final marker is the commit point. Readers cannot observe a partial
        // marker, and JSON is already closed before it becomes visible.
        String pendingName = RESULT_TXT + ".pending";
        try (FileOutputStream text = activity.openFileOutput(pendingName, Activity.MODE_PRIVATE)) {
            text.write(marker.getBytes(StandardCharsets.UTF_8));
        }
        File pending = new File(activity.getFilesDir(), pendingName);
        if (completed.exists() || !pending.renameTo(completed)) {
            throw new IOException("cannot commit smoke result marker");
        }
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            switch (ch) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                    break;
            }
        }
        return out.toString();
    }
}
