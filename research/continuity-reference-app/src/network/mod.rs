// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit opaque TCP carrier/service for QPCXCH01. Existing inner cryptography
//! supplies authentication and application encryption; TCP does not hide public
//! metadata. This is distinct from QPCNET01/TLS and is never its fallback.
pub use q_periapt_continuity_identity_candidate::session_exchange::TcpTransport;
mod framing;
mod server;
pub use server::{serve, Limits, Stats};

#[cfg(test)]
mod queue_tests;
#[cfg(test)]
mod tests;
