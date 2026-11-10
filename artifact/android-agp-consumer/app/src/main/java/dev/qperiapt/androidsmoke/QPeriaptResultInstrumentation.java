package dev.qperiapt.androidsmoke;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Result transport only: deliberately no facade, native method, or JNI exception reference. */
public final class QPeriaptResultInstrumentation extends Instrumentation {
    private static final int MAX_RESULT_BYTES = 4 * 1024 * 1024;
    private String runId;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        runId = arguments == null ? null : arguments.getString("qperiapt_run_id");
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        try {
            if (runId == null || !runId.matches("[0-9a-f]{32}")) {
                throw new IllegalArgumentException("invalid run id");
            }
            Intent intent = new Intent();
            intent.setClassName(getTargetContext().getPackageName(),
                    "dev.qperiapt.androidsmoke.QPeriaptSmokeActivity");
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.putExtra("qperiapt_run_id", runId);
            getTargetContext().startActivity(intent);
            File directory = getTargetContext().getFilesDir();
            File textFile = new File(directory, "qperiapt-android-device-result.txt");
            File jsonFile = new File(directory, "qperiapt-android-device-result.json");
            long deadline = SystemClock.elapsedRealtime() + 90_000L;
            while (SystemClock.elapsedRealtime() < deadline) {
                if (textFile.isFile() && jsonFile.isFile()) {
                    byte[] jsonBytes = readBounded(jsonFile);
                    JSONObject json = new JSONObject(new String(jsonBytes, StandardCharsets.UTF_8));
                    if (!runId.equals(json.getString("run_id"))) {
                        throw new IllegalStateException("result belongs to another run");
                    }
                    byte[] textBytes = readBounded(textFile);
                    result.putString("qperiapt_run_id", runId);
                    result.putString("qperiapt_result_text_base64", Base64.encodeToString(textBytes, Base64.NO_WRAP));
                    result.putString("qperiapt_result_json_base64", Base64.encodeToString(jsonBytes, Base64.NO_WRAP));
                    finish(Activity.RESULT_OK, result);
                    return;
                }
                SystemClock.sleep(100L);
            }
            throw new IllegalStateException("smoke result deadline exceeded");
        } catch (Throwable failure) {
            result.putString("qperiapt_run_id", runId == null ? "invalid" : runId);
            result.putString("qperiapt_transport_failure", failure.getClass().getName());
            finish(Activity.RESULT_CANCELED, result);
        }
    }

    private static byte[] readBounded(File file) throws Exception {
        if (file.length() > MAX_RESULT_BYTES) {
            throw new IllegalStateException("result exceeds limit");
        }
        try (FileInputStream input = new FileInputStream(file);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() > MAX_RESULT_BYTES - count) {
                    throw new IllegalStateException("result exceeds limit");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }
}
