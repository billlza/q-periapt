// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The ABI 2 extension's explicit process-local registry. Handles identify
//! ownership, not authorization against hostile code in the same address space.
//! Pending slots and retained operations count against separate hard bounds.

use super::{map_error, StatusResult, Q_PERIAPT_ERR_CLOSED, Q_PERIAPT_ERR_RESOURCE_LIMIT};
use crate::Q_PERIAPT_ERR_INTERNAL;
use q_periapt_sdk::{DerivedKey, HybridKey, PolicyUpdate, Runtime, SharedSecret};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

/// Cloning an entry clones a lease, never secret bytes. No backend call is made
/// under the registry lock. Keys/secrets use shared reads and exclusive disposal.
#[derive(Clone)]
pub(super) enum Object {
    Runtime(Arc<Runtime>),
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    Persistent(Arc<super::persistent::PersistentRuntime>),
    Key(Arc<RwLock<HybridKey>>),
    Secret(Arc<RwLock<SharedSecret>>),
    DerivedKey(Arc<RwLock<DerivedKey>>),
    Endpoint(Arc<q_periapt_rustls::connection::Endpoint>),
    Connection(Arc<RwLock<q_periapt_rustls::connection::Connection>>),
    PolicyUpdate {
        value: Arc<RwLock<Option<PolicyUpdate>>>,
        successor: u64,
    },
}

impl Object {
    fn is_runtime(&self) -> bool {
        match self {
            Self::Runtime(_) => true,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Self::Persistent(_) => true,
            _ => false,
        }
    }
    pub(super) fn close(&self) -> StatusResult<()> {
        match self {
            Self::Runtime(runtime) => {
                runtime.close();
                Ok(())
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Self::Persistent(owner) => owner.close(),
            Self::Endpoint(endpoint) => {
                endpoint.close();
                Ok(())
            }
            Self::Connection(connection) => match connection.write() {
                Ok(mut connection) => {
                    connection.close();
                    Ok(())
                }
                Err(poisoned) => {
                    poisoned.into_inner().close();
                    Err(Q_PERIAPT_ERR_INTERNAL)
                }
            },
            Self::Key(key) => match key.write() {
                Ok(mut key) => {
                    key.close();
                    Ok(())
                }
                Err(poisoned) => {
                    // Disposal still erases the owned key; poisoning is reported,
                    // never interpreted as permission to resume normal operations.
                    poisoned.into_inner().close();
                    Err(Q_PERIAPT_ERR_INTERNAL)
                }
            },
            Self::Secret(secret) => match secret.write() {
                Ok(mut secret) => {
                    secret.close();
                    Ok(())
                }
                Err(poisoned) => {
                    poisoned.into_inner().close();
                    Err(Q_PERIAPT_ERR_INTERNAL)
                }
            },
            Self::DerivedKey(key) => match key.write() {
                Ok(mut key) => {
                    key.close();
                    Ok(())
                }
                Err(poisoned) => {
                    poisoned.into_inner().close();
                    Err(Q_PERIAPT_ERR_INTERNAL)
                }
            },
            Self::PolicyUpdate { value, .. } => match value.write() {
                Ok(mut value) => {
                    *value = None;
                    Ok(())
                }
                Err(poisoned) => {
                    *poisoned.into_inner() = None;
                    Err(Q_PERIAPT_ERR_INTERNAL)
                }
            },
        }
    }
}

enum Slot {
    Vacant,
    Pending {
        id: u64,
        parent: u64,
        object: Option<Object>,
    },
    Live {
        id: u64,
        parent: u64,
        object: Object,
    },
}

struct Table<const N: usize> {
    next: u64,
    slots: [Slot; N],
}
impl<const N: usize> Table<N> {
    fn parent_live(&self, parent: u64) -> bool {
        parent == 0 || self.slots.iter().any(|slot|
            matches!(slot, Slot::Live { id, object, .. } if *id == parent && object.is_runtime()))
    }
}

pub(super) struct Registry<const N: usize> {
    table: Mutex<Table<N>>,
}
impl<const N: usize> Registry<N> {
    pub(super) const fn new() -> Self {
        Self {
            table: Mutex::new(Table {
                next: 1,
                slots: [const { Slot::Vacant }; N],
            }),
        }
    }
    fn lock(&self) -> StatusResult<MutexGuard<'_, Table<N>>> {
        self.table.lock().map_err(|_| Q_PERIAPT_ERR_INTERNAL)
    }
    pub(super) fn reserve(&self, parent: u64) -> StatusResult<Reservation<'_, N>> {
        let mut table = self.lock()?;
        if !table.parent_live(parent) {
            return Err(Q_PERIAPT_ERR_CLOSED);
        }
        let index = table
            .slots
            .iter()
            .position(|slot| matches!(slot, Slot::Vacant))
            .ok_or(Q_PERIAPT_ERR_RESOURCE_LIMIT)?;
        let id = table.next;
        // IDs never wrap, including when all old slots have been freed.
        let next = id.checked_add(1).ok_or(Q_PERIAPT_ERR_RESOURCE_LIMIT)?;
        let slot = table.slots.get_mut(index).ok_or(Q_PERIAPT_ERR_INTERNAL)?;
        *slot = Slot::Pending {
            id,
            parent,
            object: None,
        };
        table.next = next;
        Ok(Reservation {
            registry: self,
            index,
            id,
            published: false,
        })
    }
    pub(super) fn get(&self, handle: u64) -> StatusResult<(Object, u64)> {
        let table = self.lock()?;
        for slot in &table.slots {
            if let Slot::Live { id, parent, object } = slot {
                if *id == handle && table.parent_live(*parent) {
                    return Ok((object.clone(), *parent));
                }
            }
        }
        Err(Q_PERIAPT_ERR_CLOSED)
    }

    /// Reuse the candidate's already reserved slot under a different, previously
    /// reserved ID. No new allocation/capacity or backend call occurs at activation.
    /// The caller holds the update's write lock; table locking always follows it.
    pub(super) fn activate_policy_update(
        &self,
        handle: u64,
        owner: &Arc<RwLock<Option<PolicyUpdate>>>,
        candidate: &mut Option<PolicyUpdate>,
    ) -> StatusResult<(Reservation<'_, N>, u64)> {
        let mut table = self.lock()?;
        let (index, parent, successor) = table
            .slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot {
                Slot::Live {
                    id,
                    parent,
                    object: Object::PolicyUpdate { value, successor },
                } if *id == handle && Arc::ptr_eq(value, owner) => {
                    Some((index, *parent, *successor))
                }
                _ => None,
            })
            .ok_or(Q_PERIAPT_ERR_CLOSED)?;
        if parent == 0 || !table.parent_live(parent) {
            return Err(Q_PERIAPT_ERR_CLOSED);
        }
        let slot = table.slots.get_mut(index).ok_or(Q_PERIAPT_ERR_INTERNAL)?;
        let runtime = candidate
            .take()
            .ok_or(Q_PERIAPT_ERR_CLOSED)?
            .activate_after_persist()
            .map_err(map_error)?;
        *slot = Slot::Pending {
            id: successor,
            parent: 0,
            object: Some(Object::Runtime(runtime)),
        };
        Ok((
            Reservation {
                registry: self,
                index,
                id: successor,
                published: false,
            },
            parent,
        ))
    }
    fn take(&self, handle: u64) -> StatusResult<Object> {
        let mut table = self.lock()?;
        for slot in &mut table.slots {
            if matches!(slot, Slot::Live { id, .. } if *id == handle) {
                if let Slot::Live { object, .. } = std::mem::replace(slot, Slot::Vacant) {
                    return Ok(object);
                }
                return Err(Q_PERIAPT_ERR_INTERNAL);
            }
        }
        Err(Q_PERIAPT_ERR_CLOSED)
    }
    pub(super) fn close(&self, handle: u64) -> StatusResult<()> {
        let object = self.take(handle)?;
        let is_runtime = object.is_runtime();
        let mut result = object.close();
        if is_runtime {
            if let Err(error) = self.close_children(handle) {
                result = Err(error);
            }
        }
        result
    }
    pub(super) fn close_children(&self, handle: u64) -> StatusResult<()> {
        let mut result = Ok(());
        // Removal is the revocation point. No new child can publish after
        // it, even if generation was admitted before close. Drain known
        // children without holding the registry lock across disposal.
        loop {
            let next = {
                let table = self.lock()?;
                table.slots.iter().find_map(|slot| match slot {
                    Slot::Live { id, parent, .. } if *parent == handle => Some(*id),
                    _ => None,
                })
            };
            let Some(child) = next else {
                break;
            };
            match self.take(child) {
                Ok(child) => {
                    if let Err(error) = child.close() {
                        result = Err(error);
                    }
                }
                // A simultaneous explicit child close already owns disposal.
                Err(Q_PERIAPT_ERR_CLOSED) => {}
                Err(error) => return Err(error),
            }
        }
        result
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn reserve_persistent_successor(
        &self,
        handle: u64,
        owner: &Arc<super::persistent::PersistentRuntime>,
    ) -> StatusResult<u64> {
        let mut table = self.lock()?;
        if !table.slots.iter().any(|slot| {
            matches!(slot,
            Slot::Live { id, object: Object::Persistent(value), .. }
                if *id == handle && Arc::ptr_eq(value, owner))
        }) {
            return Err(Q_PERIAPT_ERR_CLOSED);
        }
        let successor = table.next;
        table.next = successor
            .checked_add(1)
            .ok_or(Q_PERIAPT_ERR_RESOURCE_LIMIT)?;
        Ok(successor)
    }

    /// No storage/crypto runs under this lock. The update reserved its successor
    /// ID and wrapper before committing; replacement reuses the old root slot.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn replace_persistent(
        &self,
        handle: u64,
        owner: &Arc<super::persistent::PersistentRuntime>,
        successor: u64,
        next: Arc<super::persistent::PersistentRuntime>,
    ) -> StatusResult<Reservation<'_, N>> {
        let mut table = self.lock()?;
        let index = table
            .slots
            .iter()
            .position(|slot| {
                matches!(slot,
            Slot::Live { id, object: Object::Persistent(value), .. }
                if *id == handle && Arc::ptr_eq(value, owner))
            })
            .ok_or(Q_PERIAPT_ERR_CLOSED)?;
        let slot = table.slots.get_mut(index).ok_or(Q_PERIAPT_ERR_INTERNAL)?;
        let previous = std::mem::replace(
            slot,
            Slot::Pending {
                id: successor,
                parent: 0,
                object: Some(Object::Persistent(next)),
            },
        );
        drop(table);
        // The old and successor wrappers share the store lease. Do not invoke
        // old Object::close here: that would close the newly committed runtime.
        drop(previous);
        Ok(Reservation {
            registry: self,
            index,
            id: successor,
            published: false,
        })
    }
}

/// A reservation owns rollback until the output buffers and table publication
/// are complete. Failed calls erase/dispose their unpublished object.
pub(super) struct Reservation<'a, const N: usize> {
    registry: &'a Registry<N>,
    index: usize,
    id: u64,
    published: bool,
}
impl<const N: usize> Reservation<'_, N> {
    pub(super) fn id(&self) -> u64 {
        self.id
    }
    pub(super) fn install(&mut self, value: Object) -> StatusResult<()> {
        let mut table = self.registry.lock()?;
        match table.slots.get_mut(self.index) {
            Some(Slot::Pending { id, object, .. }) if *id == self.id && object.is_none() => {
                *object = Some(value);
                Ok(())
            }
            _ => Err(Q_PERIAPT_ERR_INTERNAL),
        }
    }
    pub(super) fn install_policy_update(&mut self, update: PolicyUpdate) -> StatusResult<()> {
        // Both Arc allocations (candidate Runtime and this lock) precede host persistence.
        let value = Arc::new(RwLock::new(Some(update)));
        let mut table = self.registry.lock()?;
        let successor = table.next;
        let next = successor
            .checked_add(1)
            .ok_or(Q_PERIAPT_ERR_RESOURCE_LIMIT)?;
        match table.slots.get_mut(self.index) {
            Some(Slot::Pending { id, parent, object })
                if *id == self.id && *parent != 0 && object.is_none() =>
            {
                *object = Some(Object::PolicyUpdate { value, successor });
                table.next = next;
                Ok(())
            }
            _ => Err(Q_PERIAPT_ERR_INTERNAL),
        }
    }
    pub(super) fn publish(mut self) -> StatusResult<()> {
        let mut table = self.registry.lock()?;
        let parent = match table.slots.get(self.index) {
            Some(Slot::Pending {
                id,
                parent,
                object: Some(_),
            }) if *id == self.id => *parent,
            _ => return Err(Q_PERIAPT_ERR_INTERNAL),
        };
        if !table.parent_live(parent) {
            return Err(Q_PERIAPT_ERR_CLOSED);
        }
        let slot = table
            .slots
            .get_mut(self.index)
            .ok_or(Q_PERIAPT_ERR_INTERNAL)?;
        if let Slot::Pending {
            id,
            parent,
            object: Some(object),
        } = std::mem::replace(slot, Slot::Vacant)
        {
            *slot = Slot::Live { id, parent, object };
            self.published = true;
            Ok(())
        } else {
            Err(Q_PERIAPT_ERR_INTERNAL)
        }
    }
}
impl<const N: usize> Drop for Reservation<'_, N> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Recover a poisoned lock only for disposal. The poison bit remains,
        // so future public operations fail explicitly with ERR_INTERNAL.
        let mut table = match self.registry.table.lock() {
            Ok(table) => table,
            Err(poisoned) => poisoned.into_inner(),
        };
        let object = match table.slots.get_mut(self.index) {
            Some(slot @ Slot::Pending { .. }) => {
                if matches!(slot, Slot::Pending { id, .. } if *id == self.id) {
                    match std::mem::replace(slot, Slot::Vacant) {
                        Slot::Pending { object, .. } => object,
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        drop(table);
        // Pending objects have never been made available to another operation.
        // Dropping their sole owner releases/wipes all key/secret storage.
        drop(object);
    }
}
