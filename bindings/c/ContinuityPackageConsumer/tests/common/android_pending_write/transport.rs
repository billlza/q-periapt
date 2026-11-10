// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    path::Path,
    sync::{atomic::Ordering, Arc},
};

pub(super) enum Carrier {
    Signed,
    Native(crate::witness_tls_faults::FaultWitness),
    OpenSsl(crate::openssl_host::Host),
}
impl Carrier {
    pub(super) fn policy_tls(&self) -> Result<Option<&crate::witness_tls_faults::FaultWitness>> {
        match self {
            Self::Signed => Ok(None),
            Self::Native(server) => Ok(Some(server)),
            Self::OpenSsl(_) => {
                Err("continued policy fault requires the recorded native TLS witness".into())
            }
        }
    }
    pub(super) fn hold_query(
        &self,
        witness: &witness::Witness,
        marker: &Path,
    ) -> Result<(PathBuf, bool)> {
        let parent = marker.parent().ok_or("Query marker parent")?;
        match self {
            Self::Signed => {
                let mut held = witness
                    .hold_marker
                    .lock()
                    .map_err(|_| "Query barrier lock")?;
                if held.is_some() {
                    return Err("unconsumed signed Query barrier".into());
                }
                *held = Some(marker.to_owned());
                drop(held);
                witness.arm(4)?;
                Ok((parent.join("witness-cancelled-prefix"), false))
            }
            Self::Native(server) => {
                server.arm_reply(Some(marker), true)?;
                Ok((parent.join("witness-query-prefix"), true))
            }
            Self::OpenSsl(_) => {
                Err("this cancellation route requires the native held TLS reply".into())
            }
        }
    }
    pub(super) fn start(
        carrier: &str,
        applied: bool,
        base: &Path,
        inputs: &Path,
        peer: &Path,
        subject: p::AnchorSubject,
        witness: &witness::Witness,
    ) -> Result<Self> {
        if carrier == "signed" {
            return Ok(Self::Signed);
        }
        if carrier != "tls" {
            return Err("unknown pending recovery carrier".into());
        }
        retain(&inputs.join("witness-subject"), &subject.to_bytes())?;
        let selected = if applied {
            Self::Native(crate::witness_tls_faults::FaultWitness::start(
                Arc::clone(&witness.configured.store),
                [inputs, peer],
                witness._directory.path().join("witness.redb"),
            )?)
        } else {
            // Existing independent OpenSSL peer authenticates the complete frame
            // before withholding its first store access. The second exact leaf
            // is the fixture's already-enrolled remote endpoint, not a wildcard.
            Self::OpenSsl(crate::openssl_host::Host::start(
                base,
                [inputs, peer],
                Arc::clone(&witness.configured.store),
                true,
            )?)
        };
        let address = match &selected {
            Self::Native(s) => s.address,
            Self::OpenSsl(s) => s.address,
            Self::Signed => return Err("missing encrypted endpoint".into()),
        };
        fs::write(inputs.join("witness-address"), address.to_string())?;
        fs::write(inputs.join("witness-carrier"), b"tls")?;
        Ok(selected)
    }
    pub(super) fn captures(&self, witness: &witness::Witness) -> Result<Vec<witness::Capture>> {
        Ok(match self {
            Self::Signed => witness
                .captured
                .lock()
                .map_err(|_| "TCP captures")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.request.clone(),
                    reply: r.reply.clone(),
                    delivered: r.delivered,
                })
                .collect(),
            Self::Native(server) => server
                .captured
                .lock()
                .map_err(|_| "TLS captures")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.record.request().to_vec(),
                    reply: r.record.reply().to_vec(),
                    delivered: r.delivered,
                })
                .collect(),
            Self::OpenSsl(server) => server
                .captured
                .lock()
                .map_err(|_| "OpenSSL captures")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.request.clone(),
                    reply: r.reply.clone(),
                    delivered: true,
                })
                .collect(),
        })
    }
    pub(super) fn arm(&self, witness: &witness::Witness, applied: bool) -> Result<()> {
        match self {
            Self::Signed => witness.arm(if applied { 22 } else { 42 })?,
            Self::Native(server) => {
                assert!(applied);
                server.arm(None)?;
            }
            Self::OpenSsl(server) => {
                assert!(!applied);
                assert!(!server.drop_advance.swap(true, Ordering::AcqRel));
            }
        }
        Ok(())
    }
    pub(super) fn retain_original(
        &self,
        witness: &witness::Witness,
        applied: bool,
        before: usize,
        base: &Path,
    ) -> Result<()> {
        if applied {
            let records = self.captures(witness)?;
            let lost = records
                .get(before..)
                .ok_or("original captures")?
                .iter()
                .filter(|r| !r.delivered)
                .collect::<Vec<_>>();
            assert_eq!(lost.len(), 1);
            let record = lost.first().ok_or("original processed Advance")?;
            assert_eq!(record.request.get(204), Some(&2));
            assert_eq!(record.reply.get(204), Some(&2));
            retain(&base.join("processed-original-advance"), &record.request)?;
            retain(&base.join("original-advance-reply"), &record.reply)?;
        } else {
            let dropped = match self {
                Self::OpenSsl(server) => &server.unprocessed,
                Self::Signed => &witness.unprocessed,
                Self::Native(_) => {
                    return Err("native TLS pre-processing fault is unavailable".into())
                }
            };
            let mut dropped = dropped.lock().map_err(|_| "unprocessed Advance")?;
            assert_eq!(dropped.len(), 1);
            let request = dropped.remove(0);
            assert_eq!(request.get(204), Some(&2));
            retain(&base.join("unprocessed-original-advance"), &request)?;
            assert!(self
                .captures(witness)?
                .get(before..)
                .ok_or("original records")?
                .iter()
                .all(|r| r.request.get(204) != Some(&2)));
        }
        Ok(())
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        match self {
            Self::Signed => {}
            Self::Native(server) => server.finish()?,
            Self::OpenSsl(server) => {
                server.finish()?;
            }
        }
        Ok(())
    }
}
