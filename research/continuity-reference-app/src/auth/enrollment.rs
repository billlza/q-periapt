// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::Service;
use crate::{
    enrollment::{EnrollmentStatus, Invitation, RootInfo},
    error::Error,
};

impl Service {
    pub fn prepare_enrollment_root(&mut self, token: &str) -> Result<RootInfo, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.prepare_enrollment_root(&account)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn enrollment_root(&mut self, token: &str) -> Result<RootInfo, Error> {
        let account = self.authenticated(token)?;
        self.store.enrollment_root(&account)
    }
    pub fn invite_enrollment(
        &mut self,
        token: &str,
        request_id: [u8; 32],
    ) -> Result<Invitation, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.invite_enrollment(&account, request_id)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn approve_enrollment(
        &mut self,
        token: &str,
        operation: [u8; 32],
        request: &[u8],
    ) -> Result<(), Error> {
        let account = self.authenticated(token)?;
        self.store
            .approve_enrollment(&account, operation, request)?;
        self.authenticated(token)?;
        Ok(())
    }
    pub fn issue_enrollment(&mut self, token: &str, operation: [u8; 32]) -> Result<Vec<u8>, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.issue_enrollment(&account, operation)?;
        // A durable result may exist even if its response can no longer be released.
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn enrollment_status(
        &mut self,
        token: &str,
        operation: [u8; 32],
    ) -> Result<EnrollmentStatus, Error> {
        let account = self.authenticated(token)?;
        self.store.enrollment_status(&account, operation)
    }
    pub fn cancel_enrollment(&mut self, token: &str, operation: [u8; 32]) -> Result<(), Error> {
        let account = self.authenticated(token)?;
        self.store.cancel_enrollment(&account, operation)
    }
    pub fn suspend_enrollment_root(&mut self, token: &str) -> Result<RootInfo, Error> {
        let account = self.authenticated(token)?;
        self.store.suspend_enrollment_root(&account)
    }
}
