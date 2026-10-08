// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_host_store::{PolicyStore, StoreError};
use std::{path::Path, sync::Mutex};

pub(super) mod recovery;

#[cfg(test)]
mod tests;

pub(in crate::sdk) struct PersistentRuntime {
    pub(in crate::sdk) runtime: Arc<sdk::Runtime>,
    store: Arc<Mutex<PolicyStore>>,
}
impl PersistentRuntime {
    pub(in crate::sdk) fn close(&self) -> StatusResult<()> {
        self.runtime.close(); // revoke before waiting for any admitted disk operation
        match self.store.lock() {
            Ok(mut store) => {
                store.close();
                Ok(())
            }
            Err(poisoned) => {
                poisoned.into_inner().close();
                Err(Q_PERIAPT_ERR_INTERNAL)
            }
        }
    }
}
fn map(error: StoreError) -> i32 {
    match error {
        StoreError::Closed | StoreError::Stale => Q_PERIAPT_ERR_CLOSED,
        StoreError::Policy(error) => map_error(error),
        StoreError::RootMismatch => Q_PERIAPT_ERR_POLICY,
        StoreError::RecoveryRequired => Q_PERIAPT_ERR_RECOVERY_REQUIRED,
        StoreError::RecoveryDenied => Q_PERIAPT_ERR_POLICY,
        StoreError::RecoveryLimit => Q_PERIAPT_ERR_RESOURCE_LIMIT,
        StoreError::Busy => Q_PERIAPT_ERR_STORE_BUSY,
        StoreError::CommitUncertain(_) => Q_PERIAPT_ERR_COMMIT_UNCERTAIN,
        StoreError::ActivationAfterCommit(_) => Q_PERIAPT_ERR_STORE_COMMITTED,
        // Includes the non-exhaustive future error space: never default success.
        _ => Q_PERIAPT_ERR_STORAGE,
    }
}

pub(super) fn construct(
    path: &str,
    policy: &[u8],
    signature: &[u8],
    root: &[u8],
    limits: sdk::Limits,
    provision: bool,
) -> StatusResult<PersistentRuntime> {
    let store = if provision {
        PolicyStore::provision(Path::new(path), policy, signature, root, limits)
    } else {
        PolicyStore::open_configured(Path::new(path), policy, signature, root, limits)
    }
    .map_err(map)?;
    let runtime = store.runtime().map_err(map)?;
    Ok(PersistentRuntime {
        runtime,
        store: Arc::new(Mutex::new(store)),
    })
}

// A panic or any post-commit publication error closes BOTH the previous epoch
// and whichever epoch is now persisted. Native catch_unwind alone cannot do that.
struct FailureGuard<'a> {
    store: &'a mut PolicyStore,
    previous: &'a sdk::Runtime,
    preserve: bool,
}
impl Drop for FailureGuard<'_> {
    fn drop(&mut self) {
        if !self.preserve {
            self.previous.close();
            self.store.close();
        }
    }
}

fn update_owned<const N: usize>(
    registry: &Registry<N>,
    handle: u64,
    owner: &Arc<PersistentRuntime>,
    policy: &[u8],
    signature: &[u8],
    write_output: impl FnOnce(u64) -> StatusResult<()>,
) -> StatusResult<()> {
    let mut store = owner.store.lock().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
    // The old handle may have been closed or replaced while this call waited.
    let successor = registry.reserve_persistent_successor(handle, owner)?;
    // All native wrapper allocation and ID reservation precede the disk commit.
    let mut next = Arc::new(PersistentRuntime {
        runtime: Arc::clone(&owner.runtime),
        store: Arc::clone(&owner.store),
    });
    let mut failure = FailureGuard {
        store: &mut store,
        previous: &owner.runtime,
        preserve: false,
    };
    let next_runtime =
        match failure
            .store
            .replace_policy(owner.runtime.trusted_state(), policy, signature)
        {
            Ok(runtime) => runtime,
            Err(error) => {
                // Only documented pre-mutation failures preserve a still-live store.
                failure.preserve = matches!(error, StoreError::Policy(_) | StoreError::Stale)
                    && failure.store.runtime().is_ok();
                return Err(map(error));
            }
        };
    let publish = (|| {
        Arc::get_mut(&mut next)
            .ok_or(Q_PERIAPT_ERR_INTERNAL)?
            .runtime = next_runtime;
        write_output(successor)?;
        let slot = registry.replace_persistent(handle, owner, successor, next)?;
        registry.close_children(handle)?;
        slot.publish()
    })();
    match publish {
        Ok(()) => {
            failure.preserve = true;
            Ok(())
        }
        Err(_) => Err(Q_PERIAPT_ERR_STORE_COMMITTED),
    }
}

pub(super) fn update<const N: usize>(
    registry: &Registry<N>,
    handle: u64,
    policy: &[u8],
    signature: &[u8],
    write_output: impl FnOnce(u64) -> StatusResult<()>,
) -> StatusResult<()> {
    let owner = match registry.get(handle)?.0 {
        Object::Persistent(owner) => owner,
        Object::Runtime(_) => return Err(Q_PERIAPT_ERR_STORAGE_REQUIRED),
        _ => return Err(Q_PERIAPT_ERR_CLOSED),
    };
    let result = update_owned(registry, handle, &owner, policy, signature, write_output);
    if result.is_err() && owner.runtime.is_enabled().is_err() {
        // This runs after the store lock/FailureGuard are released. A concurrent
        // explicit close can already own disposal; do not wait while borrowing it.
        match registry.close(handle) {
            Ok(()) | Err(Q_PERIAPT_ERR_CLOSED) => {}
            Err(error) => return Err(error),
        }
        registry.close_children(handle)?;
    }
    result
}
