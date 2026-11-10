// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** One facade's ownership. No native call runs under the monitor. */
final class Owner {
    interface Call<T> { T run(long handle); }
    private final long handle;
    private int borrowed;
    private boolean transferring, transferred, closed;
    Owner(long handle) {
        if (handle == 0) throw new IllegalStateException("zero native owner");
        this.handle = handle;
    }
    private ContinuityFailure failure(int code) {
        return new ContinuityFailure("owner", code,
            code == 2 ? "owner is closed or transferred" : "owner has an active call or transfer", false);
    }
    private void available() { if (closed || transferred) throw failure(2); }
    <T> T call(boolean cancellation, Call<T> call) {
        synchronized (this) {
            available();
            if (transferring && !cancellation) throw failure(3);
            borrowed += 1;
        }
        try { return call.run(handle); }
        finally { synchronized (this) { borrowed -= 1; } }
    }
    <T> T transfer(Call<T> body) {
        synchronized (this) {
            available();
            if (transferring || borrowed != 0) throw failure(3);
            transferring = true;
        }
        try {
            T successor = body.run(handle);
            synchronized (this) { transferred = true; }
            return successor;
        } finally { synchronized (this) { transferring = false; } }
    }
    void action(int action) { call(action == 2, handle -> { Native.action(handle, action); return null; }); }
    void close() {
        synchronized (this) {
            if (transferred) return;
            available();
            if (transferring) throw failure(3);
            borrowed += 1;
        }
        try {
            try { Native.action(handle, 3); }
            catch (ContinuityFailure failure) {
                if (failure.code() == 2) synchronized (this) { closed = true; }
                throw failure;
            }
            synchronized (this) { closed = true; }
        } finally { synchronized (this) { borrowed -= 1; } }
    }
}
