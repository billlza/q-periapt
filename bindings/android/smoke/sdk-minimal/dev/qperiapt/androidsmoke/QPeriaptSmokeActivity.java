// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.androidsmoke;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;

/** Exactly one SDK facade call; full workloads cannot keep JNI methods alive here. */
public final class QPeriaptSmokeActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        String runId = getIntent().getStringExtra("qperiapt_run_id");
        List<String> passed = new ArrayList<>();
        try {
            if (runId == null || !runId.matches("[0-9a-f]{32}")) throw new IllegalArgumentException("invalid run id");
            if (!"0.2.0-alpha.1".equals(dev.qperiapt.android.QPeriaptAndroid.runtimeVersion())) {
                throw new AssertionError("version mismatch");
            }
            passed.add("runtimeVersionOnly");
            QPeriaptSmokeResults.write(this, runId, true, passed, null);
            Log.i("QPeriaptSmoke", "QPERIAPT_ANDROID_DEVICE_PASS run-id=" + runId + " tests=" + passed.size());
        } catch (Throwable failure) {
            try { QPeriaptSmokeResults.write(this, runId, false, passed, failure); }
            catch (Exception writeFailure) { failure.addSuppressed(writeFailure); }
            Log.e("QPeriaptSmoke", "QPERIAPT_ANDROID_DEVICE_FAIL run-id=" + runId, failure);
        } finally { finish(); }
    }
}
