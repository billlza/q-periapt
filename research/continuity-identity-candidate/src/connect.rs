// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One owned nonblocking TCP attempt. No worker socket survives cancellation.
use crate::Cancellation;
use mio::{Events, Interest, Poll, Token};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(25);

fn remaining(deadline: Instant, cancel: &Cancellation) -> io::Result<Duration> {
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TCP connection cancelled",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TCP connection deadline expired"))
}

pub(crate) fn tcp(
    address: SocketAddr,
    deadline: Instant,
    cancel: &Cancellation,
) -> io::Result<TcpStream> {
    observing_start(address, deadline, cancel, &mut |_| Ok(()))
}

fn observing_start(
    address: SocketAddr,
    deadline: Instant,
    cancel: &Cancellation,
    observed: &mut impl FnMut(bool) -> io::Result<()>,
) -> io::Result<TcpStream> {
    remaining(deadline, cancel)?;
    let mut poll = Poll::new()?;
    remaining(deadline, cancel)?;
    let mut stream = mio::net::TcpStream::connect(address)?;
    poll.registry()
        .register(&mut stream, Token(0), Interest::WRITABLE)?;
    // Some platforms start the OS connect during registration. Tests synchronize
    // after that real operation, without replacing its socket or outcome.
    let pending = match stream.peer_addr() {
        Ok(_) => false,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotConnected
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
            ) =>
        {
            true
        }
        // On Darwin a completed refusal can make getpeername return EINVAL.
        // Preserve the original socket error instead of classifying that
        // secondary observation as the connection outcome.
        Err(error) => return Err(stream.take_error()?.unwrap_or(error)),
    };
    observed(pending)?;
    let mut events = Events::with_capacity(4);
    loop {
        let wait = remaining(deadline, cancel)?.min(POLL_INTERVAL);
        match poll.poll(&mut events, Some(wait)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        remaining(deadline, cancel)?;
        if events.is_empty() {
            continue;
        }
        if events.iter().any(|event| event.token() != Token(0)) {
            return Err(io::Error::other("unexpected TCP readiness source"));
        }
        // Readiness can be spurious. SO_ERROR == 0 alone is not evidence that
        // TCP connected; validate both the original socket error and peer state.
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        match stream.peer_addr() {
            Ok(_) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotConnected
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            // The socket can fail after the SO_ERROR check above as well.
            Err(error) => return Err(stream.take_error()?.unwrap_or(error)),
        }
    }
    poll.registry().deregister(&mut stream)?;
    let stream: TcpStream = stream.into();
    stream.set_nonblocking(false)?;
    remaining(deadline, cancel)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    #[test]
    fn connected_ipv4_and_ipv6_streams_exchange_real_bytes() -> io::Result<()> {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address)?;
            let mut client = tcp(
                listener.local_addr()?,
                Instant::now() + Duration::from_secs(3),
                &Cancellation::default(),
            )?;
            let (mut server, _) = listener.accept()?;
            server.set_read_timeout(Some(Duration::from_secs(3)))?;
            client.write_all(b"connected")?;
            let mut bytes = [0; 9];
            server.read_exact(&mut bytes)?;
            assert_eq!(&bytes, b"connected");
        }
        Ok(())
    }

    #[test]
    fn cancelled_or_expired_admission_starts_no_connection() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        for cancelled in [false, true] {
            let cancel = Cancellation::default();
            if cancelled {
                cancel.cancel();
            }
            let deadline = if cancelled {
                Instant::now() + Duration::from_secs(3)
            } else {
                Instant::now()
            };
            let error = tcp(listener.local_addr()?, deadline, &cancel)
                .err()
                .ok_or(io::Error::other("invalid admission succeeded"))?;
            assert_eq!(
                error.kind(),
                if cancelled {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            assert_eq!(
                listener
                    .accept()
                    .err()
                    .ok_or(io::Error::other("connection was dispatched"))?
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
        Ok(())
    }

    #[test]
    fn failed_connection_retains_its_os_error() -> io::Result<()> {
        // TCP port zero cannot host a listener, avoiding a dropped-listener
        // port reuse race while exercising the real OS refusal path.
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let expected = TcpStream::connect_timeout(&address, Duration::from_secs(1))
            .err()
            .ok_or(io::Error::other("invalid endpoint unexpectedly connected"))?;
        let error = tcp(
            address,
            Instant::now() + Duration::from_secs(3),
            &Cancellation::default(),
        )
        .err()
        .ok_or(io::Error::other("refused connection succeeded"))?;
        assert_ne!(expected.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.kind(), expected.kind());
        assert_eq!(error.raw_os_error(), expected.raw_os_error());
        Ok(())
    }

    #[test]
    fn closed_listeners_preserve_refusal_across_connect_completion_races() -> io::Result<()> {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address)?;
            let address = listener.local_addr()?;
            drop(listener);
            let expected = TcpStream::connect_timeout(&address, Duration::from_secs(1))
                .expect_err("closed listener must refuse the control connection");
            assert_eq!(expected.kind(), io::ErrorKind::ConnectionRefused);
            for attempt in 0..256 {
                let error = tcp(
                    address,
                    Instant::now() + Duration::from_secs(1),
                    &Cancellation::default(),
                )
                .expect_err("closed listener must refuse the native connection");
                assert_eq!(error.kind(), expected.kind(), "attempt {attempt}: {error}");
                assert_eq!(error.raw_os_error(), expected.raw_os_error());
            }
        }
        Ok(())
    }

    fn interrupted_after_start(expire: bool) -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let cancel = Cancellation::default();
        let worker_cancel = cancel.clone();
        let deadline = Instant::now() + Duration::from_secs(3);
        let (started, ready) = mpsc::sync_channel(1);
        let (release, paused) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            observing_start(address, deadline, &worker_cancel, &mut |pending| {
                started.send(pending).map_err(io::Error::other)?;
                paused
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)
            })
        });
        let observed = ready.recv_timeout(Duration::from_secs(5));
        if expire {
            thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        } else {
            cancel.cancel();
        }
        let at = Instant::now();
        let released = release.send(());
        let result = worker
            .join()
            .map_err(|_| io::Error::other("connect worker panicked"))?;
        let was_pending = observed.map_err(io::Error::other)?;
        released.map_err(io::Error::other)?;
        let error = result
            .err()
            .ok_or(io::Error::other("interrupted connection escaped"))?;
        assert_eq!(
            error.kind(),
            if expire {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Interrupted
            }
        );
        assert!(at.elapsed() < Duration::from_secs(1));
        // Connection admission may already have completed in the kernel during
        // the test pause. In that case the owned socket must close with no data.
        match listener.accept() {
            Ok((mut accepted, _)) => {
                accepted.set_read_timeout(Some(Duration::from_secs(1)))?;
                assert_eq!(accepted.read(&mut [0; 1])?, 0);
            }
            // Cancellation may close the socket before TCP completes. In that
            // case the server has no accepted connection or application data.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        eprintln!("OS connect pending at observation: {was_pending}; expired={expire}");
        Ok(())
    }

    #[test]
    fn cancellation_after_os_connect_start_closes_without_dispatch() -> io::Result<()> {
        interrupted_after_start(false)
    }

    #[test]
    fn absolute_deadline_is_not_refreshed_after_os_connect_start() -> io::Result<()> {
        interrupted_after_start(true)
    }

    struct PendingEndpoint {
        _listener: Socket,
        _queued: Vec<TcpStream>,
        address: SocketAddr,
    }
    impl PendingEndpoint {
        fn new() -> io::Result<Self> {
            let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            listener.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
            let address = listener
                .local_addr()?
                .as_socket()
                .ok_or(io::ErrorKind::InvalidData)?;
            // Discover the host's actual bound-only behavior first. A refused
            // connection has not established a pending-state fixture, so only
            // that explicit outcome selects the bounded full-queue alternative.
            match TcpStream::connect_timeout(&address, Duration::from_millis(150)) {
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Ok(Self {
                        _listener: listener,
                        _queued: Vec::new(),
                        address,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::other(
                        "bound-only endpoint unexpectedly connected",
                    ))
                }
            }
            listener.listen(1)?;
            let mut queued = Vec::new();
            // Hold actual completed TCP connections without accepting them. A
            // bounded standard-library connect must then observe a full queue;
            // no remote blackhole, firewall change or simulated network is used.
            for _ in 0..32 {
                match TcpStream::connect_timeout(&address, Duration::from_millis(150)) {
                    Ok(stream) => queued.push(stream),
                    Err(error) if error.kind() == io::ErrorKind::TimedOut && !queued.is_empty() => {
                        return Ok(Self {
                            _listener: listener,
                            _queued: queued,
                            address,
                        });
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::other(
                "loopback backlog did not reach pending-connect condition",
            ))
        }
    }

    #[test]
    fn pending_connect_preserves_its_original_deadline() -> io::Result<()> {
        let held = PendingEndpoint::new()?;
        let start = Instant::now();
        let error = tcp(
            held.address,
            start + Duration::from_millis(150),
            &Cancellation::default(),
        )
        .err()
        .ok_or(io::Error::other("pending endpoint unexpectedly connected"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[cfg(any(feature = "connection-tls", feature = "control-tls"))]
    #[test]
    fn native_transport_preserves_cancellation_and_run_deadline_outcomes() {
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            crate::native_transport::connect(
                address,
                &cancel,
                Instant::now() + Duration::from_secs(3),
                Duration::from_secs(1)
            ),
            Err(crate::native_transport::Error::Cancelled)
        ));
        assert!(matches!(
            crate::native_transport::connect(
                address,
                &Cancellation::default(),
                Instant::now(),
                Duration::from_secs(1)
            ),
            Err(crate::native_transport::Error::Deadline)
        ));
    }

    #[test]
    fn witness_cancel_interrupts_pending_connect_before_exchange_timeout() -> io::Result<()> {
        use crate::{AnchorTcpTransport, AnchorTransport};
        let held = PendingEndpoint::new()?;
        let cancel = Cancellation::default();
        let worker_cancel = cancel.clone();
        let address = held.address;
        let (started, ready) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let mut transport = AnchorTcpTransport::with_cancellation(address, worker_cancel);
            started.send(()).map_err(io::Error::other)?;
            // Only connection admission is exercised: the full listener cannot
            // receive this framing-width placeholder as an application request.
            transport.exchange(&vec![0; 3674], Instant::now() + Duration::from_secs(3))
        });
        let announced = ready.recv_timeout(Duration::from_secs(5));
        thread::sleep(Duration::from_millis(100));
        let pending = !worker.is_finished();
        let at = Instant::now();
        cancel.cancel();
        let result = worker
            .join()
            .map_err(|_| io::Error::other("connect worker panicked"))?;
        announced.map_err(io::Error::other)?;
        assert!(
            pending,
            "exchange did not remain pending before cancellation"
        );
        let error = result
            .err()
            .ok_or(io::Error::other("cancelled connect succeeded"))?;
        let elapsed = at.elapsed();
        eprintln!(
            "pending witness connect cancellation: {elapsed:?}, {:?}",
            error.kind()
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "cancel waited for the exchange deadline"
        );
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        Ok(())
    }
}
