// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Recovery uses the same persistent owner, epoch registry and failure boundary.
use super::super::recovery::RecoveryOpenMode;
use super::*;
use q_periapt_host_store::{
    PolicyRecoveryAuthorization, PolicyRecoveryOutcome, PolicyRecoveryRequest, PolicyRecoveryTrust,
};

#[cfg(test)]
mod tests;

pub(in crate::sdk::persistent) struct Configuration<'a> {
    pub(in crate::sdk::persistent) path: &'a str,
    pub(in crate::sdk::persistent) trust: PolicyRecoveryTrust,
    pub(in crate::sdk::persistent) policy: &'a [u8],
    pub(in crate::sdk::persistent) signature: &'a [u8],
    pub(in crate::sdk::persistent) enrollment: &'a [u8],
    pub(in crate::sdk::persistent) limits: sdk::Limits,
}

pub(in crate::sdk::persistent) fn trust(
    scope: &[u8],
    initial: &[u8],
    recovery: &[u8],
) -> StatusResult<PolicyRecoveryTrust> {
    PolicyRecoveryTrust::new(
        scope.try_into().map_err(|_| Q_PERIAPT_ERR_LENGTH)?,
        initial,
        recovery,
    )
    .map_err(map)
}
pub(in crate::sdk::persistent) fn request(bytes: &[u8]) -> StatusResult<PolicyRecoveryRequest> {
    PolicyRecoveryRequest::from_bytes(bytes).map_err(map)
}
fn outcome(value: PolicyRecoveryOutcome) -> u32 {
    match value {
        PolicyRecoveryOutcome::Applied => Q_PERIAPT_POLICY_RECOVERY_APPLIED,
        PolicyRecoveryOutcome::AlreadyApplied => Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED,
        PolicyRecoveryOutcome::AppliedThenAdvanced => {
            Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED
        }
    }
}
pub(in crate::sdk::persistent) fn construct(
    config: Configuration<'_>,
    mode: RecoveryOpenMode,
    authorization: &[u8],
) -> StatusResult<(PersistentRuntime, u32)> {
    let path = Path::new(config.path);
    let (store, disposition) = match mode {
        RecoveryOpenMode::Provision => (
            PolicyStore::provision_recoverable(
                path,
                config.policy,
                config.signature,
                &config.trust,
                config.enrollment,
                config.limits,
            )
            .map_err(map)?,
            0,
        ),
        RecoveryOpenMode::Configured => (
            PolicyStore::open_recoverable_configured(
                path,
                &config.trust,
                config.policy,
                config.signature,
                config.limits,
            )
            .map_err(map)?,
            0,
        ),
        RecoveryOpenMode::Recovering => {
            let authorization =
                PolicyRecoveryAuthorization::from_bytes(authorization).map_err(map)?;
            let (store, disposition) = PolicyStore::open_recovering(
                path,
                &config.trust,
                &authorization,
                config.policy,
                config.signature,
                config.limits,
            )
            .map_err(map)?;
            (store, outcome(disposition))
        }
    };
    let runtime = store.runtime().map_err(map)?;
    Ok((
        PersistentRuntime {
            runtime,
            store: Arc::new(Mutex::new(store)),
        },
        disposition,
    ))
}
fn owner<const N: usize>(
    registry: &Registry<N>,
    handle: u64,
) -> StatusResult<Arc<PersistentRuntime>> {
    match registry.get(handle)?.0 {
        Object::Persistent(owner) => Ok(owner),
        Object::Runtime(_) => Err(Q_PERIAPT_ERR_STORAGE_REQUIRED),
        _ => Err(Q_PERIAPT_ERR_CLOSED),
    }
}
pub(in crate::sdk::persistent) fn prepare<const N: usize>(
    registry: &Registry<N>,
    handle: u64,
    operation: &[u8],
    policy: &[u8],
    signature: &[u8],
    incoming: &[u8],
) -> StatusResult<Vec<u8>> {
    let owner = owner(registry, handle)?;
    let store = owner.store.lock().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
    // A concurrent update may have changed the store while this call waited.
    owner.runtime.is_enabled().map_err(map_error)?;
    store
        .prepare_authority_recovery(
            operation.try_into().map_err(|_| Q_PERIAPT_ERR_LENGTH)?,
            policy,
            signature,
            incoming,
        )
        .map(|request| request.to_bytes())
        .map_err(map)
}

fn recover_owned<const N: usize>(
    registry: &Registry<N>,
    handle: u64,
    owner: &Arc<PersistentRuntime>,
    authorization: &PolicyRecoveryAuthorization,
    policy: &[u8],
    signature: &[u8],
    write_result: impl FnOnce(u64, u32) -> StatusResult<()>,
) -> StatusResult<()> {
    let mut store = owner.store.lock().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
    // Reserve the successor identity and allocate its wrapper BEFORE mutation.
    // Replay may leave the reserved ID unused; identifiers are never recycled.
    let successor = registry.reserve_persistent_successor(handle, owner)?;
    owner.runtime.is_enabled().map_err(map_error)?;
    let mut next = Arc::new(PersistentRuntime {
        runtime: Arc::clone(&owner.runtime),
        store: Arc::clone(&owner.store),
    });
    let mut failure = FailureGuard {
        store: &mut store,
        previous: &owner.runtime,
        preserve: false,
    };
    let disposition = match failure
        .store
        .recover_authority(authorization, policy, signature)
    {
        Ok(value) => value,
        Err(error) => {
            failure.preserve = matches!(
                error,
                StoreError::Policy(_)
                    | StoreError::Stale
                    | StoreError::RecoveryDenied
                    | StoreError::RecoveryRequired
                    | StoreError::RecoveryLimit
            ) && failure.store.runtime().is_ok();
            return Err(map(error));
        }
    };
    if disposition != PolicyRecoveryOutcome::Applied {
        // A successful replay does not revoke today's owner, keys or connections.
        failure.preserve = true;
        return write_result(0, outcome(disposition));
    }
    let publish = (|| {
        Arc::get_mut(&mut next)
            .ok_or(Q_PERIAPT_ERR_INTERNAL)?
            .runtime = failure.store.runtime().map_err(map)?;
        write_result(successor, outcome(disposition))?;
        let slot = registry.replace_persistent(handle, owner, successor, next)?;
        registry.close_children(handle)?;
        slot.publish()
    })();
    match publish {
        Ok(()) => {
            failure.preserve = true;
            Ok(())
        }
        // The durable transition succeeded; publication/disposal can still fail.
        Err(_) => Err(Q_PERIAPT_ERR_STORE_COMMITTED),
    }
}

pub(in crate::sdk::persistent) fn recover<const N: usize>(
    registry: &Registry<N>,
    handle: u64,
    authorization: &[u8],
    policy: &[u8],
    signature: &[u8],
    write_result: impl FnOnce(u64, u32) -> StatusResult<()>,
) -> StatusResult<()> {
    let owner = owner(registry, handle)?;
    let authorization = PolicyRecoveryAuthorization::from_bytes(authorization).map_err(map)?;
    let result = recover_owned(
        registry,
        handle,
        &owner,
        &authorization,
        policy,
        signature,
        write_result,
    );
    if result.is_err() && owner.runtime.is_enabled().is_err() {
        // Disposal is attempted even after a committed publication failure.
        // Preserve the commit disposition rather than misreporting a rollback.
        let close = match registry.close(handle) {
            Ok(()) | Err(Q_PERIAPT_ERR_CLOSED) => registry.close_children(handle),
            Err(error) => Err(error),
        };
        if let Err(error) = close {
            return match result {
                Err(Q_PERIAPT_ERR_STORE_COMMITTED) => Err(Q_PERIAPT_ERR_STORE_COMMITTED),
                Err(Q_PERIAPT_ERR_COMMIT_UNCERTAIN) => Err(Q_PERIAPT_ERR_COMMIT_UNCERTAIN),
                _ => Err(error),
            };
        }
    }
    result
}
