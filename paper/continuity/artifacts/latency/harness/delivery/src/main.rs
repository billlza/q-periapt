//! Supporting local delivery timings using public, unmodified 358b protocol APIs.
//! Each journal is a real distinct FileBackend in the supplied filesystem directory.
mod fixture;
use fixture::{fixture_with_options, Fixture};
use q_periapt_continuity_identity_candidate::*;
use q_periapt_sdk::expert::{PqKeySource, TraditionalKeySource};
use std::{io::Write, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

const PAIRS: usize = 16;
const SAMPLES_PER_PAIR: usize = 16;
const WARMUP_PER_PAIR: usize = 2;
const MESSAGE_BYTES: usize = 1024;
const AD: [u8; 32] = [0x41; 32];
#[repr(C)]
struct Timespec { tv_sec: i64, tv_nsec: i64 }
unsafe extern "C" { fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32; }
fn ns(id: i32) -> u64 {
    let mut t = Timespec{tv_sec:0,tv_nsec:0};
    assert_eq!(unsafe {clock_gettime(id, &mut t)},0);
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
struct Pair { f: Fixture, ji: DeviceJournal, jr: DeviceJournal, session:[u8;32], _di: tempfile::TempDir, _dr: tempfile::TempDir }
fn store(path: &Path, device: &VerifiedDevice) -> DeviceJournal {
    let key = JournalKey::provision(&path.join("key")).expect("journal key");
    let identity = JournalIdentity::generate().expect("independent journal identity");
    DeviceJournal::provision(&path.join("state.redb"), key, device, identity).expect("actual durable journal")
}
impl Pair {
    fn new(base:&Path) -> Self {
        let f=fixture_with_options(PrekeyQuality::OneTimeBoth,None,q_periapt_sdk::Limits::default(),None,
            AnchorRequirement::local_only(),ApplicationSendBudget::new(1024).unwrap(),None);
        let di=tempfile::Builder::new().prefix("sender-").permissions(std::fs::Permissions::from_mode(0o700)).tempdir_in(base).unwrap();
        let dr=tempfile::Builder::new().prefix("receiver-").permissions(std::fs::Permissions::from_mode(0o700)).tempdir_in(base).unwrap();
        let mut ji=store(&di.path().canonicalize().unwrap(),f.initiator.device(BootstrapRole::Initiator));
        let mut jr=store(&dr.path().canonicalize().unwrap(),f.responder.device(BootstrapRole::Responder));
        let request=InitiationId::generate().unwrap();
        let initial=ji.initiate(Arc::clone(&f.initiator),request,&f.signer_i,150).unwrap();
        let reply=jr.respond(Arc::clone(&f.responder),&initial,&f.signer_r,PqKeySource::from_key(&f.once),TraditionalKeySource::from_key(&f.once),150).unwrap();
        let completed=ji.accept_reply(Arc::clone(&f.initiator),request,&reply,150).unwrap();
        let session=completed.session_id();
        assert_eq!(jr.finish(Arc::clone(&f.responder),&initial,completed.final_message(),150).unwrap(),session);
        assert_eq!(ji.activate_initiator_messages(Arc::clone(&f.initiator),request,150).unwrap(),session);
        assert_eq!(jr.activate_responder_messages(Arc::clone(&f.responder),&initial,150).unwrap(),session);
        Self{f,ji,jr,session,_di:di,_dr:dr}
    }
    fn delivery(&mut self, reverse:bool, clear:&[u8], audit:bool) -> (u64,u64,u64,u64,usize) {
        let (sender,receiver,sc,rc)=if reverse {(&mut self.jr,&mut self.ji,&self.f.responder,&self.f.initiator)}else{(&mut self.ji,&mut self.jr,&self.f.initiator,&self.f.responder)};
        if audit {eprintln!("QPERIAPT_DELIVERY_BEGIN");}
        let cpu0=ns(2);let wall0=ns(4);
        let id=sender.next_message_id(sc,self.session,150).unwrap();
        let wire=sender.send_message(sc,self.session,id,clear,&AD,150).unwrap();
        let sent=ns(4);
        let received=receiver.receive_message(rc,self.session,&wire,&AD,150).unwrap();
        let wall1=ns(4);let cpu1=ns(2);
        if audit {eprintln!("QPERIAPT_DELIVERY_END");}
        assert_eq!(received.message_id(),id);assert_eq!(received.as_bytes(),clear);
        // Actual application accounting and sender acknowledgement occur outside delivery timing.
        receiver.consume_message(rc,self.session,id,150).unwrap();
        let ack=receiver.message_acknowledgement_for_epoch(rc,self.session,0,150).unwrap();
        sender.accept_message_acknowledgement(sc,self.session,&ack,150).unwrap();
        (wall1-wall0,cpu1-cpu0,sent-wall0,wall1-sent,wire.len())
    }
}
fn main(){
    let base=std::env::args().nth(1).expect("base directory argument");let base=Path::new(&base);
    assert!(base.is_dir());let mut rows=Vec::new();
    let audit=std::env::args().nth(2).as_deref()==Some("--sync-audit");
    let (pairs,samples,warmup)=if audit {(1,1,0)}else{(PAIRS,SAMPLES_PER_PAIR,WARMUP_PER_PAIR)};
    for pair in 0..pairs {
        let mut p=Pair::new(base);
        for j in 0..warmup+samples {
            let mut clear=vec![0x51;MESSAGE_BYTES];clear[..8].copy_from_slice(&(pair as u64).to_le_bytes());clear[8..16].copy_from_slice(&(j as u64).to_le_bytes());
            let reverse=j%2==1;
            let (wall,cpu,send,receive,wire_bytes)=p.delivery(reverse,&clear,audit);
            if j>=warmup {rows.push((pair,j-warmup,reverse,wall,cpu,send,receive,wire_bytes));}
        }
    }
    let mut out=std::io::BufWriter::new(std::io::stdout().lock());
    writeln!(out,"pair,sample,direction,payload_bytes,ad_bytes,frame_bytes,wall_ns,process_cpu_ns,sender_wall_ns,receiver_wall_ns").unwrap();
    for (pair,sample,reverse,wall,cpu,send,receive,wire_bytes) in rows {writeln!(out,"{pair},{sample},{},{MESSAGE_BYTES},{},{wire_bytes},{wall},{cpu},{send},{receive}",if reverse {"r_to_i"}else{"i_to_r"},AD.len()).unwrap();}
    eprintln!("pairs={pairs};samples_per_pair={samples};warmup_deliveries_per_pair={warmup};real_distinct_file_journals=true;timing=next_id_to_committed_plaintext;bootstrap_and_ack_outside=true;network=none;os_randomness_as_called_by_original_protocol=true;sync_audit={audit}");
}
