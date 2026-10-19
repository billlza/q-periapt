// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server-owned, expiring, single-use WebAuthn ceremonies and login sessions.
use crate::{
    error::Error,
    store::{Account, Store},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;

const CEREMONY_TTL: Duration = Duration::from_secs(180);
const SESSION_TTL: Duration = Duration::from_secs(900);
const MAX_PENDING: usize = 128;
const MAX_SESSIONS: usize = 128;
mod enrollment;
struct Pending {
    deadline: Instant,
    operation: Operation,
}
enum Operation {
    Register {
        account: Account,
        creating: bool,
        session: Option<String>,
        state: PasskeyRegistration,
    },
    Login {
        account: String,
        application: [u8; 32],
        state: PasskeyAuthentication,
    },
}
struct Session {
    deadline: Instant,
    account: String,
    application: [u8; 32],
}

#[derive(Serialize)]
pub struct Identity {
    pub account: String,
    pub application_id: String,
    pub passkeys: usize,
}
impl Identity {
    fn from_account(account: &Account) -> Self {
        Self {
            account: account.name.clone(),
            application_id: URL_SAFE_NO_PAD.encode(account.application_id),
            passkeys: account.passkeys.len(),
        }
    }
}
pub struct Service {
    webauthn: Webauthn,
    store: Store,
    pending: HashMap<String, Pending>,
    sessions: HashMap<String, Session>,
}
impl Service {
    pub fn new(webauthn: Webauthn, store: Store) -> Self {
        Self {
            webauthn,
            store,
            pending: HashMap::new(),
            sessions: HashMap::new(),
        }
    }
    fn prune(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, p| p.deadline > now);
        self.sessions.retain(|_, s| s.deadline > now);
    }
    fn insert(&mut self, operation: Operation, previous: Option<&str>) -> Result<String, Error> {
        self.prune();
        if let Some(id) = previous {
            self.pending.remove(id);
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::Capacity);
        }
        let token = fresh_token()?;
        if self.pending.contains_key(&token) {
            return Err(Error::Internal);
        }
        self.pending.insert(
            token.clone(),
            Pending {
                deadline: Instant::now() + CEREMONY_TTL,
                operation,
            },
        );
        Ok(token)
    }
    fn take(&mut self, token: &str) -> Result<Operation, Error> {
        self.prune();
        self.pending
            .remove(token)
            .map(|p| p.operation)
            .ok_or(Error::Unauthorized)
    }
    fn authenticated(&mut self, token: &str) -> Result<Account, Error> {
        self.prune();
        let session = self.sessions.get(token).ok_or(Error::Unauthorized)?;
        let account = self
            .store
            .account(&session.account)?
            .ok_or(Error::Unauthorized)?;
        if account.application_id != session.application {
            return Err(Error::Unauthorized);
        }
        Ok(account)
    }
    pub fn identity(&mut self, token: &str) -> Result<Identity, Error> {
        self.authenticated(token)
            .map(|a| Identity::from_account(&a))
    }
    pub fn start_registration(
        &mut self,
        name: &str,
        session: Option<&str>,
        previous: Option<&str>,
    ) -> Result<(String, CreationChallengeResponse), Error> {
        valid_name(name)?;
        let (account, creating, owner_session) = if let Some(session) = session {
            let account = self.authenticated(session)?;
            if account.name != name {
                return Err(Error::Unauthorized);
            }
            if account.passkeys.len() >= 8 {
                return Err(Error::Capacity);
            }
            (account, false, Some(session.to_owned()))
        } else {
            if self.store.account(name)?.is_some() {
                return Err(Error::Conflict(
                    "Account already exists; sign in to add a passkey",
                ));
            }
            let mut application_id = [0; 32];
            getrandom::fill(&mut application_id)
                .map_err(|e| Error::internal("account identity entropy", e))?;
            if application_id == [0; 32] {
                return Err(Error::Internal);
            }
            (
                Account {
                    name: name.into(),
                    user_handle: Uuid::new_v4(),
                    application_id,
                    passkeys: Vec::new(),
                },
                true,
                None,
            )
        };
        let exclude = if creating {
            None
        } else {
            Some(
                account
                    .passkeys
                    .iter()
                    .map(|p| p.cred_id().clone())
                    .collect(),
            )
        };
        let (options, state) = self
            .webauthn
            .start_passkey_registration(account.user_handle, name, name, exclude)
            .map_err(|e| Error::internal("start passkey registration", e))?;
        let id = self.insert(
            Operation::Register {
                account,
                creating,
                session: owner_session,
                state,
            },
            previous,
        )?;
        Ok((id, options))
    }
    pub fn finish_registration(
        &mut self,
        token: &str,
        credential: RegisterPublicKeyCredential,
        provided_session: Option<&str>,
    ) -> Result<Identity, Error> {
        let Operation::Register {
            mut account,
            creating,
            session,
            state,
        } = self.take(token)?
        else {
            return Err(Error::Unauthorized);
        };
        if session.as_deref() != provided_session {
            return Err(Error::Unauthorized);
        }
        if let Some(session) = session {
            let current = self.authenticated(&session)?;
            if current.application_id != account.application_id
                || current.user_handle != account.user_handle
            {
                return Err(Error::Unauthorized);
            }
            account = current;
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(&credential, &state)
            .map_err(|_| Error::Unauthorized)?;
        if account
            .passkeys
            .iter()
            .any(|p| p.cred_id() == passkey.cred_id())
        {
            return Err(Error::Conflict("Passkey already registered"));
        }
        account.passkeys.push(passkey);
        self.store.save(&account, creating)?;
        // Registration does not create a login session. A distinct assertion must
        // prove possession before this account can authorize a device operation.
        Ok(Identity::from_account(&account))
    }
    pub fn start_login(
        &mut self,
        name: &str,
        previous: Option<&str>,
    ) -> Result<(String, RequestChallengeResponse), Error> {
        valid_name(name)?;
        let account = self
            .store
            .account(name)?
            .ok_or(Error::AccountNotRegistered)?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&account.passkeys)
            .map_err(|e| Error::internal("start passkey authentication", e))?;
        let id = self.insert(
            Operation::Login {
                account: name.into(),
                application: account.application_id,
                state,
            },
            previous,
        )?;
        Ok((id, options))
    }
    pub fn finish_login(
        &mut self,
        token: &str,
        credential: PublicKeyCredential,
        previous: Option<&str>,
    ) -> Result<(String, Identity), Error> {
        let Operation::Login {
            account: name,
            application,
            state,
        } = self.take(token)?
        else {
            return Err(Error::Unauthorized);
        };
        let authenticated = self
            .webauthn
            .finish_passkey_authentication(&credential, &state)
            .map_err(|_| Error::Unauthorized)?;
        if !authenticated.user_verified() {
            return Err(Error::Unauthorized);
        }
        let mut account = self.store.account(&name)?.ok_or(Error::Unauthorized)?;
        if account.application_id != application {
            return Err(Error::Unauthorized);
        }
        let key = account
            .passkeys
            .iter_mut()
            .find(|p| p.cred_id() == authenticated.cred_id())
            .ok_or(Error::Unauthorized)?;
        match key.update_credential(&authenticated) {
            Some(true) => self.store.save(&account, false)?,
            Some(false) => {} // A synced passkey may legitimately have no counter update.
            None => return Err(Error::Unauthorized),
        }
        self.prune();
        if let Some(id) = previous {
            self.sessions.remove(id);
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Error::Capacity);
        }
        let id = fresh_token()?;
        if self.sessions.contains_key(&id) {
            return Err(Error::Internal);
        }
        self.sessions.insert(
            id.clone(),
            Session {
                account: name,
                application,
                deadline: Instant::now() + SESSION_TTL,
            },
        );
        Ok((id, Identity::from_account(&account)))
    }
    pub fn logout(&mut self, token: &str) -> Result<(), Error> {
        self.authenticated(token)?;
        self.sessions.remove(token).ok_or(Error::Unauthorized)?;
        Ok(())
    }
}
fn fresh_token() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| Error::internal("authentication token entropy", e))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn valid_name(name: &str) -> Result<(), Error> {
    if !(1..=64).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(Error::Invalid(
            "Use 1–64 lowercase letters, digits, underscores or hyphens",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod enrollment_tests;
#[cfg(test)]
mod tests;
