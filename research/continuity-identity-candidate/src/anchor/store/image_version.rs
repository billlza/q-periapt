// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Only recognized witness layouts may select decoding capabilities.
use super::*;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum ImageVersion {
    V1,
    V2,
    V3,
    V4,
    V6,
    V7,
    V8,
    V9,
    V10,
    V11,
    V12,
    V13,
    V14,
    V15,
    V16,
}
impl ImageVersion {
    pub(super) fn decode(tag: [u8; 8]) -> Result<Self, DurableError> {
        match &tag {
            b"QPANC001" => Ok(Self::V1),
            b"QPANC002" => Ok(Self::V2),
            b"QPANC003" => Ok(Self::V3),
            b"QPANC004" => Ok(Self::V4),
            b"QPANC006" => Ok(Self::V6),
            b"QPANC007" => Ok(Self::V7),
            b"QPANC008" => Ok(Self::V8),
            b"QPANC009" => Ok(Self::V9),
            b"QPANC010" => Ok(Self::V10),
            b"QPANC011" => Ok(Self::V11),
            b"QPANC012" => Ok(Self::V12),
            b"QPANC013" => Ok(Self::V13),
            b"QPANC014" => Ok(Self::V14),
            b"QPANC015" => Ok(Self::V15),
            b"QPANC016" => Ok(Self::V16),
            _ => Err(DurableError::Conflict),
        }
    }
}
