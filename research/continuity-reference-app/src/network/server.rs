// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Incomplete reads have bounded slots and can be evicted; they never own an SDK
//! lease. At most one complete request executes in a blocking owner worker.
use super::framing;
use q_periapt_continuity_identity_candidate as sdk;
use serde::Serialize;
use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::{AbortHandle, Id, JoinSet},
};

/// Explicit service resource bounds; these are not cryptographic peer assertions.
#[derive(Clone, Copy)]
pub struct Limits {
    /// At most 64 simultaneous incomplete frames (default eight).
    pub pending: usize,
    /// At most `pending` incomplete frames per source IP (default two).
    pub per_ip: usize,
    /// Complete frames waiting for the single owner (default zero, at most 64).
    /// Queued frames also obey `per_ip` and their original acceptance deadline.
    pub queued: usize,
    /// Deadline from TCP acceptance to complete frame (default two seconds).
    pub read_timeout: Duration,
    /// Original acceptance-to-response deadline, at most 120 seconds (default 30).
    pub operation_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pending: 8,
            per_ip: 2,
            queued: 0,
            read_timeout: Duration::from_secs(2),
            operation_timeout: Duration::from_secs(30),
        }
    }
}
impl Limits {
    fn check(self) -> io::Result<()> {
        if !(1..=64).contains(&self.pending)
            || !(1..=self.pending).contains(&self.per_ip)
            || self.queued > 64
            || self.read_timeout.is_zero()
            || self.read_timeout > self.operation_timeout
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(120)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}
/// Local service observations. A completed response is not a peer consumption proof.
#[derive(Default, Serialize)]
pub struct Stats {
    pub accepted: u64,
    pub evicted_incomplete: u64,
    pub rejected_busy: u64,
    pub queued_requests: u64,
    pub expired_queued: u64,
    pub read_errors: u64,
    pub completed_responses: u64,
    pub operation_errors: u64,
    pub last_operation_error: Option<String>,
}
struct Reading {
    abort: AbortHandle,
    ip: IpAddr,
}
struct Inbound {
    stream: TcpStream,
    frame: Vec<u8>,
    deadline: Instant,
    ip: IpAddr,
}
type ReadResult = Result<(Id, io::Result<Inbound>), tokio::task::JoinError>;

struct Work {
    active: JoinSet<io::Result<()>>,
    ready: VecDeque<Inbound>,
    capacity: usize,
    per_ip: usize,
}
impl Work {
    fn expire(&mut self, stats: &mut Stats) {
        let now = Instant::now();
        self.ready.retain(|request| {
            if request.deadline <= now {
                stats.expired_queued += 1;
                false
            } else {
                true
            }
        });
    }
    fn admit<F>(
        &mut self,
        inbound: Inbound,
        handler: &Arc<F>,
        stop: &sdk::Cancellation,
        stats: &mut Stats,
    ) where
        F: Fn(&[u8], &sdk::session_exchange::Run<'_>) -> io::Result<Vec<u8>>
            + Send
            + Sync
            + 'static,
    {
        self.expire(stats);
        if self.active.is_empty() && self.ready.is_empty() {
            execute(inbound, &mut self.active, handler, stop);
        } else if self.ready.len() < self.capacity
            && self.ready.iter().filter(|r| r.ip == inbound.ip).count() < self.per_ip
        {
            self.ready.push_back(inbound);
            stats.queued_requests += 1;
        } else {
            stats.rejected_busy += 1;
        }
    }
}

fn dispatch<F>(
    result: ReadResult,
    readers: &mut Vec<Reading>,
    work: &mut Work,
    handler: &Arc<F>,
    stop: &sdk::Cancellation,
    stats: &mut Stats,
) -> io::Result<()>
where
    F: Fn(&[u8], &sdk::session_exchange::Run<'_>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
{
    let id = match &result {
        Ok((id, _)) => *id,
        Err(error) => error.id(),
    };
    readers.retain(|value| value.abort.id() != id);
    let inbound = match result {
        Ok((_, Ok(value))) => value,
        Ok((_, Err(_))) => {
            stats.read_errors += 1;
            return Ok(());
        }
        Err(error) if error.is_cancelled() => return Ok(()),
        Err(error) => return Err(io::Error::other(error)),
    };
    work.admit(inbound, handler, stop, stats);
    Ok(())
}

fn execute<F>(
    inbound: Inbound,
    work: &mut JoinSet<io::Result<()>>,
    handler: &Arc<F>,
    stop: &sdk::Cancellation,
) where
    F: Fn(&[u8], &sdk::session_exchange::Run<'_>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
{
    let handler = Arc::clone(handler);
    let stop = stop.clone();
    work.spawn(async move {
        let Inbound {
            mut stream,
            frame,
            deadline,
            ip: _,
        } = inbound;
        let cancel = sdk::Cancellation::default();
        let worker_cancel = cancel.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            let run = sdk::session_exchange::Run::until(&worker_cancel, deadline)
                .map_err(|e| io::Error::other(e.to_string()))?;
            handler(&frame, &run)
        });
        let response = tokio::select! {
            biased;
            _=framing::cancelled(&stop)=>{
                cancel.cancel();worker.await.map_err(io::Error::other)??;
                return Err(io::ErrorKind::Interrupted.into());
            }
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))=>{
                cancel.cancel();worker.await.map_err(io::Error::other)??;
                return Err(io::ErrorKind::TimedOut.into());
            }
            result=&mut worker=>result.map_err(io::Error::other)??,
        };
        framing::write(&mut stream, &response, deadline, &stop).await
    });
}

/// Serve one separately configured peer context through `handler`. No request can
/// select trust roots here. Complete SDK operations serialize; a configured queue
/// retains bounded complete frames under their original deadlines. Overflow closes
/// without a fabricated result. Oldest incomplete reads are evicted at global or
/// per-IP capacity. Cancel `stop` and await this future to join owned tasks/workers.
/// Do not abort/drop the service future: that cannot join blocking callbacks.
/// A callback must honor its own bounded I/O contract; shutdown waits for its exit.
pub async fn serve<F>(
    listener: TcpListener,
    limits: Limits,
    stop: sdk::Cancellation,
    handler: F,
) -> io::Result<Stats>
where
    F: Fn(&[u8], &sdk::session_exchange::Run<'_>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
{
    limits.check()?;
    let handler = Arc::new(handler);
    let mut stats = Stats::default();
    let mut reads = JoinSet::new();
    let mut readers: Vec<Reading> = Vec::new();
    let mut work = Work {
        active: JoinSet::new(),
        ready: VecDeque::new(),
        capacity: limits.queued,
        per_ip: limits.per_ip,
    };
    let result:io::Result<()>=async {
        loop {
            work.expire(&mut stats);
            if !stop.is_cancelled() && work.active.is_empty() {
                if let Some(inbound) = work.ready.pop_front() {
                    execute(inbound, &mut work.active, &handler, &stop);
                }
            }
            let queued_deadline=work.ready.iter().map(|request|request.deadline).min();
            tokio::select! {
                biased;
                _=framing::cancelled(&stop)=>break,
                result=work.active.join_next(),if !work.active.is_empty()=>match result {
                    Some(Ok(Ok(())))=>stats.completed_responses+=1,
                    Some(Ok(Err(error)))=>{stats.operation_errors+=1;stats.last_operation_error=Some(error.kind().to_string());}
                    Some(Err(error))=>return Err(io::Error::other(error)),
                    None=>return Err(io::Error::other("active network worker disappeared")),
                },
                _=async {
                    if let Some(deadline)=queued_deadline {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                    }
                },if queued_deadline.is_some()=>work.expire(&mut stats),
                result=reads.join_next_with_id(),if !reads.is_empty()=>{
                    dispatch(result.ok_or_else(||io::Error::other("active network read disappeared"))?,&mut readers,&mut work,&handler,&stop,&mut stats)?;
                }
                accepted=listener.accept()=>{
                    let (mut stream,address)=accepted?;stats.accepted+=1;
                    let accepted=Instant::now();let ip=address.ip();
                    let same_ip=readers.iter().filter(|value|value.ip==ip).count();
                    let victim=if same_ip>=limits.per_ip { readers.iter().find(|value|value.ip==ip) }
                        else if readers.len()>=limits.pending { readers.first() } else { None };
                    if let Some(victim)=victim {
                        victim.abort.abort();stats.evicted_incomplete+=1;
                        // Do not spawn replacements until an owned read has ended.
                        // One newly accepted socket is held while joining eviction.
                        loop {
                            let result=reads.join_next_with_id().await.ok_or_else(||io::Error::other("evicted network read disappeared"))?;
                            dispatch(result,&mut readers,&mut work,&handler,&stop,&mut stats)?;
                            if readers.len()<limits.pending && readers.iter().filter(|value|value.ip==ip).count()<limits.per_ip { break; }
                        }
                    }
                    let read_stop=stop.clone();
                    let abort=reads.spawn(async move {
                        stream.set_nodelay(true)?;
                        let frame=framing::read(&mut stream,accepted+limits.read_timeout,&read_stop).await?;
                        Ok(Inbound {stream,frame,deadline:accepted+limits.operation_timeout,ip})
                    });
                    readers.push(Reading {abort,ip});
                }
            }
        }
        Ok(())
    }.await;
    let mut failure = result.err();
    stop.cancel();
    // Queued input has never entered an owner. Shutdown drops those sockets;
    // only the already executing callback must be joined and reconciled.
    work.ready.clear();
    reads.abort_all();
    while let Some(result) = reads.join_next().await {
        if let Err(error) = result {
            if !error.is_cancelled() && failure.is_none() {
                failure = Some(io::Error::other(error));
            }
        }
    }
    while let Some(result) = work.active.join_next().await {
        match result {
            Ok(Ok(())) => stats.completed_responses += 1,
            Ok(Err(error)) => {
                stats.operation_errors += 1;
                stats.last_operation_error = Some(error.kind().to_string());
            }
            Err(error) => {
                if failure.is_none() {
                    failure = Some(io::Error::other(error));
                }
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(stats)
}
