// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded native control delivery over the SDK's standard mutually authenticated
//! TLS connection. TLS carrier acknowledgements never advance protocol state.
use crate::native_transport::{check, remaining, retryable};
pub use crate::native_transport::{Cancellation, Error, RunLimits};
use crate::{BootstrapContext, DeviceJournal, DeviceSigningKey, RekeyControlStep};
use q_periapt_rustls::connection::{Credentials, Endpoint, Limits};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

mod socket;
use socket::Channel;

const MAGIC: &[u8; 8] = b"QPCCTL01";
use crate::contract::MAX_CONTROL_BYTES as MAX_CONTROL;

/// Result established by local authenticated journal state, not an independently
/// authenticated acknowledgement of peer receipt or a secrecy-recovery proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completed {
    /// Exact locally confirmed target.
    pub epoch: u64,
    /// All exchanges, including failed attempts, in this invocation.
    pub exchanges: u16,
}

/// Exclusive journal actor borrowed for one bounded invocation. The caller keeps
/// ownership and can reconcile, apply roster updates or close it after return.
pub struct Session<'a> {
    /// Exact existing device journal; no implicit provision or reset occurs.
    pub journal: &'a mut DeviceJournal,
    /// Independently authenticated context matching the endpoint binding.
    pub context: &'a BootstrapContext,
    /// Controlled device signing owner for this journal's role.
    pub signer: &'a DeviceSigningKey,
}

/// Explicit target and transport policy for one client invocation.
pub struct Run<'a> {
    /// Existing or next target; retries retain this exact value.
    pub target: u64,
    /// Explicit selected TCP peer, with a nonzero port.
    pub address: SocketAddr,
    /// TLS certificate name, checked in addition to the exact certificate pin.
    pub server_name: &'a str,
    /// Finite exchange, duration and connect bounds.
    pub limits: RunLimits,
    /// Cancellation never clears the durable target or changes its randomness.
    pub cancel: &'a Cancellation,
}

/// Standard TLS endpoint pinned to one Continuity context and session, alongside
/// the SDK's policy binding and both exact peer certificate checks.
pub struct ControlEndpoint {
    endpoint: Endpoint,
    context: [u8; 32],
    session: [u8; 32],
    client: bool,
}
impl ControlEndpoint {
    fn new(
        context: &BootstrapContext,
        session: [u8; 32],
        credentials: Credentials<'_>,
        limits: Limits,
        client: bool,
    ) -> Result<Self, Error> {
        crate::codec::nonzero(&session).map_err(Error::Authority)?;
        let mut binding = b"Q-PERIAPT-CONTINUITY-CONTROL-TLS/v1/".to_vec();
        binding.extend_from_slice(&context.digest());
        binding.extend_from_slice(&session);
        let runtime = Arc::clone(&context.policy().runtime);
        let endpoint = if client {
            Endpoint::client(runtime, credentials, &binding, limits)?
        } else {
            Endpoint::server(runtime, credentials, &binding, limits)?
        };
        Ok(Self {
            endpoint,
            context: context.digest(),
            session,
            client,
        })
    }
    /// Create the active TCP/TLS client. Its role is independent of rekey proposer parity.
    pub fn client(
        context: &BootstrapContext,
        session: [u8; 32],
        credentials: Credentials<'_>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(context, session, credentials, limits, true)
    }
    /// Create a pinned TLS server for this exact pairwise session.
    pub fn server(
        context: &BootstrapContext,
        session: [u8; 32],
        credentials: Credentials<'_>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(context, session, credentials, limits, false)
    }
    /// Revoke endpoint use and its current SDK connections. Cancel ongoing socket
    /// I/O using the cancellation handle as well.
    pub fn close(&self) {
        self.endpoint.close();
    }
    fn binding(&self, context: &BootstrapContext) -> Result<(), Error> {
        if self.context != context.digest() {
            return Err(Error::Binding);
        }
        Ok(())
    }

    /// Deliver one exact target with finite retries over fresh/reused TLS connections.
    /// `clock` supplies current trusted protocol time at every admission and I/O wake.
    /// Only classified transient network errors are retried. Durable, signature,
    /// identity, policy, cancellation and deadline failures return immediately.
    pub fn run(
        &self,
        session: Session<'_>,
        run: Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Completed, Error> {
        let Session {
            journal,
            context,
            signer,
        } = session;
        let Run {
            target,
            address,
            server_name,
            limits,
            cancel,
        } = run;
        self.binding(context)?;
        if !self.client {
            return Err(Error::InvalidOptions);
        }
        crate::native_transport::address(address)?;
        let deadline = limits.deadline()?;
        check(context, cancel, deadline, &mut clock)?;
        let mut step = journal.start_control_delivery(
            context,
            self.session,
            target,
            signer,
            clock().map_err(Error::Clock)?,
        )?;
        let mut channel: Option<Channel> = None;
        for attempt in 1..=limits.exchanges {
            check(context, cancel, deadline, &mut clock)?;
            let message = match step {
                RekeyControlStep::LocallyConfirmed(epoch) => {
                    if epoch != target {
                        return Err(Error::Protocol);
                    }
                    return Ok(Completed {
                        epoch,
                        exchanges: attempt - 1,
                    });
                }
                RekeyControlStep::Output(message) => message,
            };
            if message.target_epoch() != target {
                return Err(Error::Protocol);
            }
            let wire = journal.replay_control_delivery(
                context,
                self.session,
                &message,
                signer,
                clock().map_err(Error::Clock)?,
            )?;
            check(context, cancel, deadline, &mut clock)?;
            let result = (|| {
                if channel.is_none() {
                    let remaining = remaining(deadline)?.min(limits.connect_timeout);
                    let stream = TcpStream::connect_timeout(&address, remaining)?;
                    check(context, cancel, deadline, &mut clock)?;
                    channel = Some(Channel::new(stream, self.endpoint.connect(server_name)?)?);
                }
                channel
                    .as_mut()
                    .ok_or(Error::Protocol)?
                    .exchange(&wire, context, cancel, deadline, &mut clock)
            })();
            match result {
                Ok(Some(reply)) => {
                    check(context, cancel, deadline, &mut clock)?;
                    // A valid old receipt is still not a reply for this run.
                    // Check the target before allowing duplicate reconciliation.
                    require_target(&reply, target)?;
                    step = journal.receive_rekey_control(
                        context,
                        self.session,
                        &reply,
                        signer,
                        clock().map_err(Error::Clock)?,
                    )?;
                    if let RekeyControlStep::LocallyConfirmed(epoch) = step {
                        if epoch != target {
                            return Err(Error::Protocol);
                        }
                        check(context, cancel, deadline, &mut clock)?;
                        return Ok(Completed {
                            epoch,
                            exchanges: attempt,
                        });
                    }
                }
                Ok(None) => {
                    check(context, cancel, deadline, &mut clock)?;
                    match journal.advance_rekey_control(
                        context,
                        self.session,
                        target,
                        signer,
                        clock().map_err(Error::Clock)?,
                    )? {
                        RekeyControlStep::LocallyConfirmed(epoch) => {
                            if epoch != target {
                                return Err(Error::Protocol);
                            }
                            return Ok(Completed {
                                epoch,
                                exchanges: attempt,
                            });
                        }
                        RekeyControlStep::Output(_) => return Err(Error::Protocol),
                    }
                }
                Err(error) if retryable(&error) => {
                    channel = None;
                    check(context, cancel, deadline, &mut clock)?;
                    if attempt == limits.exchanges {
                        return Err(Error::RetryExhausted {
                            attempts: attempt,
                            last: Box::new(error),
                        });
                    }
                    step = RekeyControlStep::Output(message);
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::AttemptsExhausted)
    }

    /// Serve one accepted TLS connection with finite request and time bounds.
    /// A locally completed target is flushed before this call returns. Keep the
    /// listener available for exact replay after a lost final response.
    pub fn serve(
        &self,
        stream: TcpStream,
        session: Session<'_>,
        limits: RunLimits,
        cancel: &Cancellation,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Completed, Error> {
        let Session {
            journal,
            context,
            signer,
        } = session;
        self.binding(context)?;
        if self.client {
            return Err(Error::InvalidOptions);
        }
        let deadline = limits.deadline()?;
        check(context, cancel, deadline, &mut clock)?;
        let mut channel = Channel::new(stream, self.endpoint.accept()?)?;
        for exchanges in 1..=limits.exchanges {
            let request = channel.request(context, cancel, deadline, &mut clock)?;
            check(context, cancel, deadline, &mut clock)?;
            #[cfg(all(test, unix))]
            if let Some(reply) = test_support::override_reply()? {
                channel.respond(
                    request.id(),
                    reply.as_deref(),
                    context,
                    cancel,
                    deadline,
                    &mut clock,
                )?;
                channel.finish(context, cancel, deadline, &mut clock)?;
                return Err(Error::Protocol);
            }
            let step = journal.receive_rekey_control(
                context,
                self.session,
                request.bytes(),
                signer,
                clock().map_err(Error::Clock)?,
            )?;
            let (target, response) = match step {
                RekeyControlStep::Output(message) => (message.target_epoch(), Some(message)),
                RekeyControlStep::LocallyConfirmed(epoch) => (epoch, None),
            };
            let wire = match &response {
                Some(message) => Some(journal.replay_control_delivery(
                    context,
                    self.session,
                    message,
                    signer,
                    clock().map_err(Error::Clock)?,
                )?),
                None => None,
            };
            #[cfg(all(test, unix))]
            test_support::after_committed_reply(request.bytes(), wire.as_deref())?;
            channel.respond(
                request.id(),
                wire.as_deref(),
                context,
                cancel,
                deadline,
                &mut clock,
            )?;
            if journal
                .rekey_progress(context, self.session)?
                .confirmed_epoch
                >= target
            {
                check(context, cancel, deadline, &mut clock)?;
                channel.finish(context, cancel, deadline, &mut clock)?;
                return Ok(Completed {
                    epoch: target,
                    exchanges,
                });
            }
        }
        Err(Error::AttemptsExhausted)
    }
}

fn require_target(wire: &[u8], expected: u64) -> Result<(), Error> {
    let (body, _) = crate::crypto::open_envelope(wire).map_err(|_| Error::Protocol)?;
    let bytes = body.get(112..120).ok_or(Error::Protocol)?;
    let target = u64::from_be_bytes(bytes.try_into().map_err(|_| Error::Protocol)?);
    if target != expected {
        return Err(Error::Protocol);
    }
    Ok(())
}
#[cfg(all(test, unix))]
mod test_support {
    use super::*;
    use std::{fs, io::Write, path::Path};

    pub(super) fn override_reply() -> io::Result<Option<Option<Vec<u8>>>> {
        match std::env::var("QPERIAPT_CONTROL_TLS_MODE").as_deref() {
            Ok("empty") => Ok(Some(None)),
            Ok("replay") => {
                let path = std::env::var_os("QPERIAPT_CONTROL_TLS_DIR")
                    .ok_or(io::ErrorKind::InvalidInput)?;
                Ok(Some(Some(fs::read(
                    Path::new(&path).join("tls-old-receipt"),
                )?)))
            }
            _ => Ok(None),
        }
    }
    fn save(path: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        let pending = path.join(format!("{name}-pending"));
        let mut file = fs::File::create_new(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(pending, path.join(name))
    }
    pub(super) fn after_committed_reply(input: &[u8], reply: Option<&[u8]>) -> io::Result<()> {
        let mode = std::env::var("QPERIAPT_CONTROL_TLS_MODE").ok();
        let stage = match reply.and_then(|wire| wire.get(4..12)) {
            Some(b"QPRKOF01") => "cut-offer",
            Some(b"QPRKRP01") => "cut-response",
            Some(b"QPRKFN01") => "cut-final",
            Some(b"QPRKRC01") => "cut-receipt",
            None if reply.is_none() => "cut-ack",
            _ => return Ok(()),
        };
        if mode.as_deref() != Some(stage) {
            return Ok(());
        }
        let path =
            std::env::var_os("QPERIAPT_CONTROL_TLS_DIR").ok_or(io::ErrorKind::InvalidInput)?;
        let path = Path::new(&path);
        save(path, "tls-cut-input", input)?;
        if let Some(reply) = reply {
            save(path, "tls-cut-output", reply)?;
        }
        save(path, "tls-cut-ready", stage.as_bytes())?;
        loop {
            std::thread::park();
        }
    }
}
