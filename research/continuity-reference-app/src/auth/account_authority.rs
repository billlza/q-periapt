// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::account_authority::{Association, AssociationRequest};
use crate::account_authority::{Cutover, CutoverRequest, Retirement};
impl Service {
    pub fn approve_account_root(
        &mut self,
        token: &str,
        request: &CutoverRequest,
    ) -> Result<Cutover, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.approve_account_root(&account, request)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn commit_account_root(
        &mut self,
        token: &str,
        operation: [u8; 32],
        proof: &Retirement,
    ) -> Result<Cutover, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.commit_account_root(&account, operation, proof)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn close_account_root(
        &mut self,
        token: &str,
        operation: [u8; 32],
        receipt: &[u8],
    ) -> Result<Cutover, Error> {
        let account = self.authenticated(token)?;
        let result = self
            .store
            .close_account_root(&account, operation, receipt)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn resume_account_root(
        &mut self,
        token: &str,
        operation: [u8; 32],
    ) -> Result<Cutover, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.resume_account_root(&account, operation)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn account_root_cutover(
        &mut self,
        token: &str,
        operation: [u8; 32],
    ) -> Result<Cutover, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.account_root_cutover(&account, operation)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn retired_account_root(
        &mut self,
        token: &str,
        revision: u64,
    ) -> Result<crate::enrollment::RootInfo, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.retired_account_root(&account, revision)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn associate_account_authority(
        &mut self,
        token: &str,
        request: &AssociationRequest,
    ) -> Result<Association, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.associate_account_authority(&account, request)?;
        self.authenticated(token)?;
        Ok(result)
    }
    pub fn account_authority(&mut self, token: &str) -> Result<Association, Error> {
        let account = self.authenticated(token)?;
        let result = self.store.account_authority(&account)?;
        self.authenticated(token)?;
        Ok(result)
    }
}
