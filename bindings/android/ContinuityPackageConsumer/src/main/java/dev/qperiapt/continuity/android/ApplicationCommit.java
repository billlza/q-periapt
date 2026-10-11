// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Synchronous application transaction on the thread calling serve.
 * Return only after the effect and original session/message deduplication record
 * are durable together. Throw on refusal or an unknown result; a retry may call
 * this again with the same IDs, so reconcile that original transaction.
 * Plaintext is a temporary copy cleared on return. Copy it explicitly if needed.
 * Reentrant peer operations/close are busy; cancellation remains permitted.
 */
@FunctionalInterface
public interface ApplicationCommit {
    void commit(Ids.Session session, Ids.Message message, byte[] plaintext) throws Exception;
}
