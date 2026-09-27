// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.androidsmoke;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;

public final class QPeriaptSmokeActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        String runId = getIntent().getStringExtra("qperiapt_run_id");
        List<String> passed = new ArrayList<>();
        try {
            if (runId == null || !runId.matches("[0-9a-f]{32}")) throw new IllegalArgumentException("invalid run id");
            QPeriaptSDKWorkload.run(getAssets(), passed);
            QPeriaptSmokeResults.write(this, runId, true, passed, null);
        } catch (Throwable failure) {
            try { QPeriaptSmokeResults.write(this, runId, false, passed, failure); }
            catch (Exception writeFailure) { failure.addSuppressed(writeFailure); }
            Log.e("QPeriaptSmoke", "SDK owner consumer failed", failure);
        } finally { finish(); }
    }
}
