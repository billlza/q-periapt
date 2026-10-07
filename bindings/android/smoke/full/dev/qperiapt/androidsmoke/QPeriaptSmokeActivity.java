package dev.qperiapt.androidsmoke;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;

public final class QPeriaptSmokeActivity extends Activity {
    private static final String TAG = "QPeriaptSmoke";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String runId = getIntent().getStringExtra("qperiapt_run_id");
        if (runId == null || !runId.matches("[0-9a-f]{32}")) {
            runId = "invalid-run-id";
        }
        List<String> passed = new ArrayList<String>();
        try {
            new QPeriaptSmokeWorkload(getAssets()).run(passed);
            QPeriaptSmokeResults.write(this, runId, true, passed, null);
            Log.i(TAG, "QPERIAPT_ANDROID_DEVICE_PASS run-id=" + runId + " tests=" + passed.size());
        } catch (Throwable t) {
            try {
                QPeriaptSmokeResults.write(this, runId, false, passed, t);
            } catch (Throwable ignored) {
                Log.e(TAG, "failed to write result", ignored);
            }
            Log.e(TAG, "QPERIAPT_ANDROID_DEVICE_FAIL run-id=" + runId, t);
        } finally {
            finish();
        }
    }

}
