//! Durable single-slot client journal for Authority Wire V3 operations.
//!
//! The remote authority store owns authoritative state and its bounded
//! receipt table. This module owns the complementary client-side crash protocol:
//! an exact intent is committed before dispatch, an exact authenticated receipt
//! replaces it after reconciliation, and only that durable resolved state may be
//! acknowledged. The live lease fence remains process-local and is never restored
//! from these records.

use core::fmt;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};

use crate::authority::{
    AuthorityEpochV2, AuthorityIntentV2, AuthorityReceiptV2, ReceiptAckDispositionV2,
};
use crate::authority_codec::{
    decode_config, decode_intent, decode_receipt, decode_state_head, encode_config, encode_intent,
    encode_receipt, encode_state_head,
};
use crate::authority_protocol::{
    receipt_command, AuthorityClientIdV3, AuthorityServerIdV3, AuthorityWireIdentityV3,
    DurablyRetainedAuthorityReceiptV3,
};
use crate::codec::{encode_domain, require_domain, Decoder, Encoder, MAX_FRAME_BYTES};

const JOURNAL_SCHEMA_VERSION: u16 = 3;
const BINDING_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-AUTHORITY-BINDING/v3";
const ACTIVE_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-AUTHORITY-ACTIVE/v3";
const CHECKPOINT_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-AUTHORITY-CHECKPOINT/v3";

const BINDING_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("agent_authority_binding_v3");
const ACTIVE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("agent_authority_active_v3");
const CHECKPOINT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("agent_authority_checkpoint_v3");
const SINGLETON_KEY: &str = "record";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityJournalError {
    CorruptStore,
    AuthorityBindingMismatch,
    OperationPending,
    ReceiptMismatch,
    NoPendingOperation,
    #[cfg(test)]
    CommitUncertain,
}

impl fmt::Display for AuthorityJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "authority journal failure: {self:?}")
    }
}

impl std::error::Error for AuthorityJournalError {}

/// Exact durable state of the sole authority operation that may need recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableAuthorityOperation {
    /// The exact intent is durable, but no exact receipt has been durably resolved.
    Prepared(AuthorityIntentV2),
    /// The exact authenticated receipt is durable and may be acknowledged.
    Resolved(AuthorityReceiptV2),
}

impl DurableAuthorityOperation {
    pub(crate) const fn intent(self) -> AuthorityIntentV2 {
        match self {
            Self::Prepared(intent) => intent,
            Self::Resolved(receipt) => receipt.intent(),
        }
    }

    pub(crate) fn retained(
        self,
    ) -> Result<DurablyRetainedAuthorityReceiptV3, AuthorityJournalError> {
        match self {
            Self::Prepared(_) => Err(AuthorityJournalError::ReceiptMismatch),
            Self::Resolved(receipt) => {
                DurablyRetainedAuthorityReceiptV3::after_repository_commit(receipt)
                    .map_err(|_| AuthorityJournalError::ReceiptMismatch)
            }
        }
    }
}

pub(crate) fn provision_tables(
    transaction: &WriteTransaction,
) -> Result<(), AuthorityJournalError> {
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let checkpoint = transaction
        .open_table(CHECKPOINT_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    if binding
        .len()
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        != 0
        || active
            .len()
            .map_err(|_| AuthorityJournalError::CorruptStore)?
            != 0
        || checkpoint
            .len()
            .map_err(|_| AuthorityJournalError::CorruptStore)?
            != 0
    {
        return Err(AuthorityJournalError::CorruptStore);
    }
    Ok(())
}

pub(crate) fn validate(database: &Database) -> Result<(), AuthorityJournalError> {
    let transaction = database
        .begin_read()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let binding_table = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let active_table = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let checkpoint_table = transaction
        .open_table(CHECKPOINT_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding_table)?;
    require_singleton(&active_table)?;
    require_singleton(&checkpoint_table)?;

    let binding = binding_table
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .map(|value| decode_binding(value.value()))
        .transpose()?;
    let active = active_table
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .map(|value| decode_active(value.value()))
        .transpose()?;
    let checkpoint = checkpoint_table
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .map(|value| decode_checkpoint(value.value()))
        .transpose()?;
    match (binding, active, checkpoint) {
        (None, None, None) => Ok(()),
        (Some(identity), active, checkpoint) => {
            if active.is_some_and(|operation| !operation_matches(identity, operation))
                || checkpoint.is_some_and(|receipt| !receipt_matches(identity, receipt))
                || !sequence_is_valid(active, checkpoint)
            {
                return Err(AuthorityJournalError::CorruptStore);
            }
            Ok(())
        }
        _ => Err(AuthorityJournalError::CorruptStore),
    }
}

pub(crate) fn bind(
    transaction: &WriteTransaction,
    identity: AuthorityWireIdentityV3,
) -> Result<(), AuthorityJournalError> {
    let mut table = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&table)?;
    let existing = table
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .map(|value| value.value().to_vec());
    match existing {
        Some(value) if decode_binding(&value)? == identity => Ok(()),
        Some(_) => Err(AuthorityJournalError::AuthorityBindingMismatch),
        None => {
            let encoded = encode_binding(identity)?;
            table
                .insert(SINGLETON_KEY, encoded.as_slice())
                .map_err(|_| AuthorityJournalError::CorruptStore)?;
            Ok(())
        }
    }
}

pub(crate) fn bound_identity(
    database: &Database,
) -> Result<Option<AuthorityWireIdentityV3>, AuthorityJournalError> {
    let transaction = database
        .begin_read()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let table = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&table)?;
    table
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .map(|value| decode_binding(value.value()))
        .transpose()
}

pub(crate) fn advance_binding(
    transaction: &WriteTransaction,
    expected: AuthorityWireIdentityV3,
    next: AuthorityWireIdentityV3,
) -> Result<(), AuthorityJournalError> {
    if expected.client_id() != next.client_id()
        || expected.server_id() != next.server_id()
        || expected.authority_epoch() != next.authority_epoch()
        || expected.config() != next.config()
        || expected.state_head() == next.state_head()
    {
        return Err(AuthorityJournalError::AuthorityBindingMismatch);
    }
    let mut table = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&table)?;
    require_binding(&table, expected)?;
    let encoded = encode_binding(next)?;
    table
        .insert(SINGLETON_KEY, encoded.as_slice())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(())
}

pub(crate) fn require_terminal(
    transaction: &WriteTransaction,
    identity: AuthorityWireIdentityV3,
) -> Result<(), AuthorityJournalError> {
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding)?;
    require_binding(&binding, identity)?;
    let active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&active)?;
    if active
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .is_some()
    {
        return Err(AuthorityJournalError::OperationPending);
    }
    Ok(())
}

pub(crate) fn active(
    database: &Database,
    identity: AuthorityWireIdentityV3,
) -> Result<Option<DurableAuthorityOperation>, AuthorityJournalError> {
    let transaction = database
        .begin_read()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding)?;
    require_binding(&binding, identity)?;
    let active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&active)?;
    let operation = active
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .map(|value| decode_active(value.value()))
        .transpose()?;
    if operation.is_some_and(|value| !operation_matches(identity, value)) {
        return Err(AuthorityJournalError::CorruptStore);
    }
    Ok(operation)
}

pub(crate) fn prepare(
    transaction: &WriteTransaction,
    identity: AuthorityWireIdentityV3,
    intent: AuthorityIntentV2,
) -> Result<(), AuthorityJournalError> {
    if !intent_matches(identity, intent) {
        return Err(AuthorityJournalError::ReceiptMismatch);
    }
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding)?;
    require_binding(&binding, identity)?;
    drop(binding);
    let mut active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&active)?;
    if active
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .is_some()
    {
        return Err(AuthorityJournalError::OperationPending);
    }
    let checkpoint = transaction
        .open_table(CHECKPOINT_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&checkpoint)?;
    if let Some(previous) = checkpoint
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
    {
        let previous = decode_checkpoint(previous.value())?;
        if previous.resulting_authority_version() > intent.expected_authority_version() {
            return Err(AuthorityJournalError::ReceiptMismatch);
        }
    }
    drop(checkpoint);
    let encoded = encode_active(DurableAuthorityOperation::Prepared(intent))?;
    active
        .insert(SINGLETON_KEY, encoded.as_slice())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(())
}

pub(crate) fn resolve(
    transaction: &WriteTransaction,
    identity: AuthorityWireIdentityV3,
    intent: AuthorityIntentV2,
    receipt: AuthorityReceiptV2,
) -> Result<(), AuthorityJournalError> {
    if receipt.intent() != intent || !receipt_matches(identity, receipt) {
        return Err(AuthorityJournalError::ReceiptMismatch);
    }
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding)?;
    require_binding(&binding, identity)?;
    drop(binding);
    let mut active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&active)?;
    let stored = active
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .ok_or(AuthorityJournalError::NoPendingOperation)?;
    if decode_active(stored.value())? != DurableAuthorityOperation::Prepared(intent) {
        return Err(AuthorityJournalError::ReceiptMismatch);
    }
    drop(stored);
    let encoded = encode_active(DurableAuthorityOperation::Resolved(receipt))?;
    active
        .insert(SINGLETON_KEY, encoded.as_slice())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(())
}

pub(crate) fn cancel_prepared(
    transaction: &WriteTransaction,
    identity: AuthorityWireIdentityV3,
    intent: AuthorityIntentV2,
) -> Result<(), AuthorityJournalError> {
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding)?;
    require_binding(&binding, identity)?;
    drop(binding);
    let mut active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&active)?;
    let stored = active
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .ok_or(AuthorityJournalError::NoPendingOperation)?;
    if decode_active(stored.value())? != DurableAuthorityOperation::Prepared(intent) {
        return Err(AuthorityJournalError::ReceiptMismatch);
    }
    drop(stored);
    active
        .remove(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(())
}

pub(crate) fn complete_acknowledgement(
    transaction: &WriteTransaction,
    identity: AuthorityWireIdentityV3,
    retained: DurablyRetainedAuthorityReceiptV3,
    disposition: ReceiptAckDispositionV2,
) -> Result<(), AuthorityJournalError> {
    let binding = transaction
        .open_table(BINDING_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&binding)?;
    require_binding(&binding, identity)?;
    drop(binding);
    let mut active = transaction
        .open_table(ACTIVE_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&active)?;
    let stored = active
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
        .ok_or(AuthorityJournalError::NoPendingOperation)?;
    let DurableAuthorityOperation::Resolved(receipt) = decode_active(stored.value())? else {
        return Err(AuthorityJournalError::ReceiptMismatch);
    };
    if receipt != retained.receipt() {
        return Err(AuthorityJournalError::ReceiptMismatch);
    }
    drop(stored);

    let encoded = encode_checkpoint(receipt, disposition)?;
    let mut checkpoint = transaction
        .open_table(CHECKPOINT_TABLE)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    require_singleton(&checkpoint)?;
    if let Some(previous) = checkpoint
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
    {
        let previous = decode_checkpoint(previous.value())?;
        if previous.resulting_authority_version() >= receipt.resulting_authority_version() {
            return Err(AuthorityJournalError::ReceiptMismatch);
        }
    }
    checkpoint
        .insert(SINGLETON_KEY, encoded.as_slice())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    active
        .remove(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(())
}

fn require_singleton(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<(), AuthorityJournalError> {
    let length = table
        .len()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    if length > 1 {
        return Err(AuthorityJournalError::CorruptStore);
    }
    if length == 1
        && table
            .get(SINGLETON_KEY)
            .map_err(|_| AuthorityJournalError::CorruptStore)?
            .is_none()
    {
        return Err(AuthorityJournalError::CorruptStore);
    }
    Ok(())
}

fn sequence_is_valid(
    active: Option<DurableAuthorityOperation>,
    checkpoint: Option<AuthorityReceiptV2>,
) -> bool {
    let Some(checkpoint) = checkpoint else {
        return true;
    };
    match active {
        None => true,
        Some(DurableAuthorityOperation::Prepared(intent)) => {
            checkpoint.resulting_authority_version() <= intent.expected_authority_version()
        }
        Some(DurableAuthorityOperation::Resolved(receipt)) => {
            checkpoint.resulting_authority_version() < receipt.resulting_authority_version()
        }
    }
}

fn require_binding(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    identity: AuthorityWireIdentityV3,
) -> Result<(), AuthorityJournalError> {
    match table
        .get(SINGLETON_KEY)
        .map_err(|_| AuthorityJournalError::CorruptStore)?
    {
        Some(value) if decode_binding(value.value())? == identity => Ok(()),
        Some(_) => Err(AuthorityJournalError::AuthorityBindingMismatch),
        None => Err(AuthorityJournalError::AuthorityBindingMismatch),
    }
}

fn operation_matches(
    identity: AuthorityWireIdentityV3,
    operation: DurableAuthorityOperation,
) -> bool {
    match operation {
        DurableAuthorityOperation::Prepared(intent) => intent_matches(identity, intent),
        DurableAuthorityOperation::Resolved(receipt) => receipt_matches(identity, receipt),
    }
}

fn intent_matches(identity: AuthorityWireIdentityV3, intent: AuthorityIntentV2) -> bool {
    intent.expected_config() == identity.config() && receipt_command_for_intent(intent).is_some()
}

fn receipt_matches(identity: AuthorityWireIdentityV3, receipt: AuthorityReceiptV2) -> bool {
    receipt.intent().expected_config() == identity.config() && receipt_command(&receipt).is_some()
}

fn receipt_command_for_intent(
    intent: AuthorityIntentV2,
) -> Option<crate::authority_protocol::AuthorityCommandV3> {
    crate::authority_protocol::mutation_command(intent.mutation())
}

fn encode_binding(identity: AuthorityWireIdentityV3) -> Result<Vec<u8>, AuthorityJournalError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, BINDING_DOMAIN, JOURNAL_SCHEMA_VERSION)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .fixed(identity.client_id().as_bytes())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .fixed(identity.server_id().as_bytes())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .fixed(identity.authority_epoch().as_bytes())
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .fixed(&encode_state_head(identity.state_head()))
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .fixed(&encode_config(identity.config()))
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(encoder.finish())
}

fn decode_binding(bytes: &[u8]) -> Result<AuthorityWireIdentityV3, AuthorityJournalError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, BINDING_DOMAIN, JOURNAL_SCHEMA_VERSION)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let client_id = AuthorityClientIdV3::from_bytes(
        decoder
            .array()
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
    )
    .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let server_id = AuthorityServerIdV3::from_bytes(
        decoder
            .array()
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
    )
    .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let authority_epoch = AuthorityEpochV2::from_bytes(
        decoder
            .array()
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
    )
    .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let state_head = decode_state_head(
        decoder
            .fixed(112)
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
    )
    .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let config = decode_config(
        decoder
            .fixed(40)
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
    )
    .map_err(|_| AuthorityJournalError::CorruptStore)?;
    decoder
        .finish()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    AuthorityWireIdentityV3::new(client_id, server_id, authority_epoch, state_head, config)
        .map_err(|_| AuthorityJournalError::CorruptStore)
}

fn encode_active(operation: DurableAuthorityOperation) -> Result<Vec<u8>, AuthorityJournalError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, ACTIVE_DOMAIN, JOURNAL_SCHEMA_VERSION)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    match operation {
        DurableAuthorityOperation::Prepared(intent) => {
            encoder
                .byte(1)
                .map_err(|_| AuthorityJournalError::CorruptStore)?;
            encode_intent(&mut encoder, intent).map_err(|_| AuthorityJournalError::CorruptStore)?;
        }
        DurableAuthorityOperation::Resolved(receipt) => {
            encoder
                .byte(2)
                .map_err(|_| AuthorityJournalError::CorruptStore)?;
            let encoded =
                encode_receipt(receipt).map_err(|_| AuthorityJournalError::CorruptStore)?;
            encoder
                .lp16(&encoded)
                .map_err(|_| AuthorityJournalError::CorruptStore)?;
        }
    }
    Ok(encoder.finish())
}

fn decode_active(bytes: &[u8]) -> Result<DurableAuthorityOperation, AuthorityJournalError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, ACTIVE_DOMAIN, JOURNAL_SCHEMA_VERSION)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let operation = match decoder
        .byte()
        .map_err(|_| AuthorityJournalError::CorruptStore)?
    {
        1 => DurableAuthorityOperation::Prepared(
            decode_intent(&mut decoder).map_err(|_| AuthorityJournalError::CorruptStore)?,
        ),
        2 => DurableAuthorityOperation::Resolved(
            decode_receipt(
                decoder
                    .lp16(MAX_FRAME_BYTES)
                    .map_err(|_| AuthorityJournalError::CorruptStore)?,
            )
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
        ),
        _ => return Err(AuthorityJournalError::CorruptStore),
    };
    decoder
        .finish()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(operation)
}

fn encode_checkpoint(
    receipt: AuthorityReceiptV2,
    disposition: ReceiptAckDispositionV2,
) -> Result<Vec<u8>, AuthorityJournalError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, CHECKPOINT_DOMAIN, JOURNAL_SCHEMA_VERSION)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .byte(match disposition {
            ReceiptAckDispositionV2::Removed => 1,
            ReceiptAckDispositionV2::AlreadyAbsent => 2,
        })
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    let encoded = encode_receipt(receipt).map_err(|_| AuthorityJournalError::CorruptStore)?;
    encoder
        .lp16(&encoded)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(encoder.finish())
}

fn decode_checkpoint(bytes: &[u8]) -> Result<AuthorityReceiptV2, AuthorityJournalError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, CHECKPOINT_DOMAIN, JOURNAL_SCHEMA_VERSION)
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    match decoder
        .byte()
        .map_err(|_| AuthorityJournalError::CorruptStore)?
    {
        1 | 2 => {}
        _ => return Err(AuthorityJournalError::CorruptStore),
    }
    let receipt = decode_receipt(
        decoder
            .lp16(MAX_FRAME_BYTES)
            .map_err(|_| AuthorityJournalError::CorruptStore)?,
    )
    .map_err(|_| AuthorityJournalError::CorruptStore)?;
    decoder
        .finish()
        .map_err(|_| AuthorityJournalError::CorruptStore)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use redb::{Database, Durability};

    use super::{
        active, bind, complete_acknowledgement, prepare, provision_tables, resolve, validate,
        AuthorityJournalError, DurableAuthorityOperation,
    };
    use crate::authority::{
        AuthorityDispositionV2, AuthorityEpochV2, AuthorityIntentV2, AuthorityMutationV2,
        AuthorityReceiptV2, AuthorityRejectionV2, DeploymentConfigRevisionV2, OperationIdV2,
        ProcessInstanceIdV2, ReceiptAckDispositionV2, StateFenceV2, StateHeadV2, StateRevisionV2,
    };
    use crate::authority_protocol::{
        AuthorityClientIdV3, AuthorityServerIdV3, AuthorityWireIdentityV3,
        DurablyRetainedAuthorityReceiptV3,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn identity(seed: u8) -> TestResult<AuthorityWireIdentityV3> {
        Ok(AuthorityWireIdentityV3::new(
            AuthorityClientIdV3::from_bytes([seed; 32])?,
            AuthorityServerIdV3::from_bytes([seed.wrapping_add(1); 32])?,
            AuthorityEpochV2::from_bytes([seed.wrapping_add(2); 32])?,
            StateHeadV2::new(
                StateRevisionV2::new(1, [seed.wrapping_add(3); 32], 1, [seed + 4; 32])?,
                StateFenceV2::from_bytes([seed.wrapping_add(5); 32])?,
            ),
            DeploymentConfigRevisionV2::new(1, [seed.wrapping_add(6); 32])?,
        )?)
    }

    fn intent(identity: AuthorityWireIdentityV3, random: u8) -> TestResult<AuthorityIntentV2> {
        Ok(AuthorityIntentV2::new(
            OperationIdV2::new(1, [random; 32])?,
            1,
            identity.config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([random.wrapping_add(1); 32])?,
            },
        )?)
    }

    fn write(
        database: &Database,
        operation: impl FnOnce(&redb::WriteTransaction) -> Result<(), AuthorityJournalError>,
    ) -> Result<(), AuthorityJournalError> {
        let mut transaction = database
            .begin_write()
            .map_err(|_| AuthorityJournalError::CorruptStore)?;
        transaction.set_durability(Durability::Immediate);
        transaction.set_two_phase_commit(true);
        operation(&transaction)?;
        transaction
            .commit()
            .map_err(|_| AuthorityJournalError::CommitUncertain)
    }

    #[test]
    fn single_slot_requires_durable_prepare_resolve_and_ack_terminal_order() -> TestResult {
        let directory = tempfile::tempdir()?;
        let database = Database::create(directory.path().join("lease-journal.redb"))?;
        write(&database, provision_tables)?;
        let identity = identity(11)?;
        write(&database, |transaction| bind(transaction, identity))?;
        let intent = intent(identity, 31)?;
        write(&database, |transaction| {
            prepare(transaction, identity, intent)
        })?;
        assert_eq!(
            active(&database, identity)?,
            Some(DurableAuthorityOperation::Prepared(intent))
        );
        assert_eq!(
            write(&database, |transaction| prepare(
                transaction,
                identity,
                intent
            )),
            Err(AuthorityJournalError::OperationPending)
        );

        let receipt = AuthorityReceiptV2::restore(intent, AuthorityDispositionV2::Applied, 2)
            .map_err(|_| "receipt restore failed")?;
        write(&database, |transaction| {
            resolve(transaction, identity, intent, receipt)
        })?;
        let resolved = active(&database, identity)?.ok_or("resolved operation missing")?;
        assert_eq!(resolved, DurableAuthorityOperation::Resolved(receipt));
        let retained = resolved.retained()?;
        write(&database, |transaction| {
            complete_acknowledgement(
                transaction,
                identity,
                retained,
                ReceiptAckDispositionV2::Removed,
            )
        })?;
        assert_eq!(active(&database, identity)?, None);
        assert_eq!(
            write(&database, |transaction| {
                prepare(transaction, identity, intent)
            }),
            Err(AuthorityJournalError::ReceiptMismatch)
        );
        validate(&database)?;
        Ok(())
    }

    #[test]
    fn exact_authority_binding_and_receipt_are_not_substitutable() -> TestResult {
        let directory = tempfile::tempdir()?;
        let database = Database::create(directory.path().join("lease-binding.redb"))?;
        write(&database, provision_tables)?;
        let first = identity(21)?;
        let second = identity(41)?;
        write(&database, |transaction| bind(transaction, first))?;
        let substitutions = [
            AuthorityWireIdentityV3::new(
                second.client_id(),
                first.server_id(),
                first.authority_epoch(),
                first.state_head(),
                first.config(),
            )?,
            AuthorityWireIdentityV3::new(
                first.client_id(),
                second.server_id(),
                first.authority_epoch(),
                first.state_head(),
                first.config(),
            )?,
            AuthorityWireIdentityV3::new(
                first.client_id(),
                first.server_id(),
                second.authority_epoch(),
                first.state_head(),
                first.config(),
            )?,
            AuthorityWireIdentityV3::new(
                first.client_id(),
                first.server_id(),
                first.authority_epoch(),
                second.state_head(),
                first.config(),
            )?,
            AuthorityWireIdentityV3::new(
                first.client_id(),
                first.server_id(),
                first.authority_epoch(),
                first.state_head(),
                second.config(),
            )?,
        ];
        for substitution in substitutions {
            assert_eq!(
                write(&database, |transaction| bind(transaction, substitution)),
                Err(AuthorityJournalError::AuthorityBindingMismatch)
            );
            assert_eq!(
                active(&database, substitution),
                Err(AuthorityJournalError::AuthorityBindingMismatch)
            );
        }
        let first_intent = intent(first, 51)?;
        write(&database, |transaction| {
            prepare(transaction, first, first_intent)
        })?;
        let foreign_intent = intent(first, 61)?;
        let foreign_receipt =
            AuthorityReceiptV2::restore(foreign_intent, AuthorityDispositionV2::Applied, 2)
                .map_err(|_| "foreign receipt restore failed")?;
        assert_eq!(
            write(&database, |transaction| {
                resolve(transaction, first, first_intent, foreign_receipt)
            }),
            Err(AuthorityJournalError::ReceiptMismatch)
        );
        assert_eq!(
            active(&database, first)?,
            Some(DurableAuthorityOperation::Prepared(first_intent))
        );

        let first_receipt = AuthorityReceiptV2::restore(
            first_intent,
            AuthorityDispositionV2::Applied,
            first_intent.expected_authority_version() + 1,
        )
        .map_err(|_| "first receipt restore failed")?;
        write(&database, |transaction| {
            resolve(transaction, first, first_intent, first_receipt)
        })?;
        let conflicting_receipt = AuthorityReceiptV2::restore(
            first_intent,
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseGenerationMismatch),
            first_intent.expected_authority_version() + 1,
        )
        .map_err(|_| "conflicting receipt restore failed")?;
        let conflicting_retained =
            DurablyRetainedAuthorityReceiptV3::after_repository_commit(conflicting_receipt)?;
        assert_eq!(
            write(&database, |transaction| {
                complete_acknowledgement(
                    transaction,
                    first,
                    conflicting_retained,
                    ReceiptAckDispositionV2::Removed,
                )
            }),
            Err(AuthorityJournalError::ReceiptMismatch)
        );
        assert_eq!(
            active(&database, first)?,
            Some(DurableAuthorityOperation::Resolved(first_receipt))
        );
        Ok(())
    }
}
