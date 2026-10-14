// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original catalogue object identity and the sole permitted secret retirement.
use super::*;

pub(crate) struct SecretRecord {
    pub(crate) identity: [u8; 32],
    pub(crate) revision: u32,
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}
fn snapshot(lease: &HostSecret) -> Result<SecretRecord, DurableError> {
    let id = lease.secret_identity().map_err(error)?;
    if id.length() != 32 {
        return Err(DurableError::Corrupt);
    }
    let mut identity = [0; 32];
    id.copy_to(&mut identity);
    crate::codec::nonzero(&identity)?;
    let revision = lease.secret_revision().map_err(error)?;
    let bytes = lease.secret_bytes().map_err(error)?;
    if !matches!(revision, 1 | 2) || bytes.length() > 65536 {
        return Err(DurableError::Corrupt);
    }
    Ok(SecretRecord {
        identity,
        revision,
        bytes: Zeroizing::new(bytes.to_vec()),
    })
}
impl Storage {
    pub(crate) async fn read_signer_record(
        &self,
        value: &Path,
    ) -> Result<SecretRecord, DurableError> {
        let lease = self.root.read_secret(path(value)?).await.map_err(error)?;
        after_cleanup(snapshot(&lease), lease.close_secret().map_err(error))
    }
    pub(crate) async fn retire_signer_record(
        &self,
        value: &Path,
        check: impl FnOnce(&SecretRecord) -> Result<bool, DurableError>,
    ) -> Result<(), DurableError> {
        let name = path(value)?;
        let lease = self.root.read_secret(name).await.map_err(error)?;
        let result = async {
            let record = snapshot(&lease)?;
            if check(&record)? {
                return Ok(());
            }
            self.root.retire_signer(name, &lease).await.map_err(error)
        }
        .await;
        after_cleanup(result, lease.close_secret().map_err(error))
    }
}
