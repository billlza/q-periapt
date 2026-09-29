// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Finite passive disclosures of actual durable reservations, not a recovery proof.
use super::*;
use crate::durable::tests::ChildGuard;
use q_periapt_sdk::{
    expert::replay::{RecoveryKey, SealedOperation},
    Ciphertext, PublicKey, Runtime, CIPHERTEXT_LEN,
};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
enum Cut {
    KeyReserved,
    EncapsulationReserved,
}
impl Cut {
    fn stage(self) -> &'static str {
        match self {
            Self::KeyReserved => "rekey-key-reserved",
            Self::EncapsulationReserved => "rekey-response-kem-reserved",
        }
    }
    fn token_len(self) -> usize {
        match self {
            Self::KeyReserved => 277,
            Self::EncapsulationReserved => 245,
        }
    }
}

// This is the attacker's complete private input. No journal, signer, live root
// or later reservation is reachable through it after capture. Runtime admission
// below supplies only the already authenticated public policy configuration.
struct Disclosure {
    cut: Cut,
    journal: [u8; 32],
    root: ZeroizingBytes<32>,
    host_key: ZeroizingBytes<32>,
    token: SealedOperation,
}
impl Disclosure {
    fn capture(cut: Cut, journal: &mut DeviceJournal, session: &[u8; 32]) -> Self {
        let image = journal
            .image()
            .expect("durable reservation after process loss");
        let payload = &image
            .records
            .get(&record_id(session))
            .expect("state")
            .payload;
        let prior = State::decode(payload).expect("authenticated checkpoint");
        assert_eq!((prior.send_epoch, prior.receive_epoch), (0, 0));
        let token = SealedOperation::from_bytes(
            payload
                .get(payload.len() - cut.token_len()..)
                .expect("exact final reservation field"),
        )
        .expect("sealed reservation");
        Self {
            cut,
            journal: image.id,
            root: prior.rekey,
            host_key: key(journal.active.as_ref().expect("open").key.0.as_bytes())
                .expect("one-time wrapping key disclosure"),
            token,
        }
    }

    fn recover_shared(
        &self,
        recovery: &RecoveryKey,
        runtime: &Runtime,
        offer: &[u8],
        response: &[u8],
    ) -> Result<ZeroizingBytes<32>, q_periapt_sdk::Error> {
        let (body, _) = crate::crypto::open_envelope(offer).expect("public offer");
        let prefix = body.get(..153).expect("offer profile/context/epoch prefix");
        let operation = rekey_digest(b"operation", &[self.journal.as_slice(), prefix].concat());
        let peer = PublicKey::from_bytes(body.get(153..).expect("public hybrid key"))?;
        let (response_body, _) = crate::crypto::open_envelope(response).expect("public response");
        let ciphertext = Ciphertext::from_bytes(
            response_body
                .get(185..185 + CIPHERTEXT_LEN)
                .expect("public ciphertext"),
        )?;
        let context = rekey_digest(b"response-kem", offer);
        match self.cut {
            Cut::KeyReserved => {
                let owner = recovery.generate_key(
                    runtime,
                    &rekey_digest(b"key", &operation),
                    &self.token,
                )?;
                assert_eq!(owner.public_key()?.to_bytes(), peer.to_bytes());
                owner
                    .decapsulate(&ciphertext, &context)?
                    .export_for_protocol()
            }
            Cut::EncapsulationReserved => {
                let scope = rekey_digest(
                    b"response-operation",
                    &[
                        self.journal.as_slice(),
                        &operation,
                        &rekey_digest(b"offer-wire", offer),
                    ]
                    .concat(),
                );
                let result = recovery.encapsulate(runtime, &scope, &peer, &context, &self.token)?;
                assert_eq!(result.ciphertext.to_bytes(), ciphertext.to_bytes());
                result.secret.export_for_protocol()
            }
        }
    }

    fn predict_traffic(&self, runtime: &Runtime, offer: &[u8], response: &[u8]) -> [Traffic; 2] {
        let mut wrong_key = key(self.host_key.as_bytes()).expect("negative control");
        *wrong_key.as_mut_bytes().first_mut().expect("key byte") ^= 1;
        let wrong = RecoveryKey::from_host_key(wrong_key.as_bytes()).expect("wrong wrapping key");
        assert!(matches!(
            self.recover_shared(&wrong, runtime, offer, response),
            Err(q_periapt_sdk::Error::InvalidPrivateKey)
        ));
        let recovery = RecoveryKey::from_host_key(self.host_key.as_bytes()).expect("disclosed key");
        let shared = self
            .recover_shared(&recovery, runtime, offer, response)
            .expect("reserved entropy predicts the future hybrid contribution");
        let (response_body, _) = crate::crypto::open_envelope(response).expect("public response");
        let core = response_body
            .get(..185 + CIPHERTEXT_LEN)
            .expect("response core");
        let mut info =
            b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/pending-root/HKDF-SHA256/".to_vec();
        info.extend_from_slice(&rekey_digest(b"response-core", core));
        let mut root = ZeroizingBytes::<32>::zeroed();
        Hkdf::<Sha256>::new(Some(self.root.as_bytes()), shared.as_bytes())
            .expand(&info, root.as_mut_bytes())
            .expect("predicted next root");

        let (offer_body, _) = crate::crypto::open_envelope(offer).expect("public offer");
        let context = offer_body.get(40..72).expect("public context digest");
        let session: [u8; 32] = offer_body
            .get(72..104)
            .expect("public session")
            .try_into()
            .expect("width");
        let target = u64::from_be_bytes(
            offer_body
                .get(112..120)
                .expect("target")
                .try_into()
                .expect("width"),
        );
        assert_eq!(target, 1);
        let mut info =
            b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/epoch-traffic/HKDF-SHA256/ChaCha20Poly1305/"
                .to_vec();
        info.extend_from_slice(context);
        info.extend_from_slice(&target.to_be_bytes());
        info.extend_from_slice(&rekey_digest(
            b"traffic-transcript",
            &[offer, response].concat(),
        ));
        let mut material = ZeroizingBytes::<128>::zeroed();
        Hkdf::<Sha256>::new(Some(&session), root.as_bytes())
            .expand(&info, material.as_mut_bytes())
            .expect("predicted traffic owners");
        [
            Traffic::from_material(session, 2, target, material.as_bytes())
                .expect("intercept initiator"),
            Traffic::from_material(session, 1, target, material.as_bytes())
                .expect("intercept responder"),
        ]
    }
}

fn kill_after_reservation(p: &mut Pair, cut: Cut, offer: Option<&[u8]>) -> Disclosure {
    let path = match cut {
        Cut::KeyReserved => {
            p.ji.close();
            &p.pi
        }
        Cut::EncapsulationReserved => {
            p.jr.close();
            &p.pr
        }
    };
    let mut public =
        p.f.reusable
            .public_key()
            .expect("public")
            .to_bytes()
            .to_vec();
    public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
    fs::write(path.join("public-keys"), public).expect("fixture public keys");
    fs::write(path.join("session"), p.session).expect("session");
    fs::write(
        path.join("operation"),
        match cut {
            Cut::KeyReserved => "rekey",
            Cut::EncapsulationReserved => "rekey-response",
        },
    )
    .expect("operation");
    if let Some(offer) = offer {
        fs::write(path.join("rekey-offer"), offer).expect("public offer");
    }
    let log = fs::File::create_new(path.join("disclosure-child.log")).expect("child log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::messages::tests::message_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
            .env("QPERIAPT_MESSAGES_STAGE", cut.stage())
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "reservation was not committed before the deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(path.join("ready")).expect("cut"),
        cut.stage()
    );
    assert!(
        !path.join("rekey-effect").exists(),
        "KEM computation must not precede this cut"
    );
    assert!(!path.join("returned").exists());
    child.0.kill().expect("kill owned child");
    assert!(!child.0.wait().expect("reap").success());
    match cut {
        Cut::KeyReserved => {
            p.ji = reopen(path, p.f.initiator_device());
            assert_eq!(
                p.ji.rekey_offer_status(&p.f.initiator, p.session)
                    .expect("phase"),
                RekeyOfferStatus::KeyReserved
            );
            Disclosure::capture(cut, &mut p.ji, &p.session)
        }
        Cut::EncapsulationReserved => {
            p.jr = reopen(path, p.f.local_device());
            assert_eq!(
                p.jr.rekey_response_status(&p.f.responder, p.session)
                    .expect("phase"),
                RekeyResponseStatus::EncapsulationReserved
            );
            Disclosure::capture(cut, &mut p.jr, &p.session)
        }
    }
}

fn reservation_disclosure(cut: Cut) {
    let mut p = Pair::new();
    p.activate();
    let early_offer = if matches!(cut, Cut::EncapsulationReserved) {
        Some(
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("offer before response reservation"),
        )
    } else {
        None
    };
    let disclosed = kill_after_reservation(&mut p, cut, early_offer.as_deref());
    // From this point the predictor gets only the captured snapshot, public
    // policy, control wires and ciphertext. Identity owners stay with the peers.
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("resume exact offer");
    if let Some(early) = early_offer {
        assert_eq!(early, offer);
    }
    let response =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("resume exact response");
    let runtime = match cut {
        Cut::KeyReserved => &p.f.initiator.policy().runtime,
        Cut::EncapsulationReserved => &p.f.responder.policy().runtime,
    };
    let [mut intercept_i, mut intercept_r] = disclosed.predict_traffic(runtime, &offer, &response);
    assert_eq!(complete_rekey(&mut p), 1);
    p.ji.close();
    p.jr.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    p.jr = reopen(&p.pr, p.f.local_device());
    let mut recovered = 0;
    for _ in 0..3 {
        for from_initiator in [true, false] {
            let (sender, receiver, sc, rc, intercept) = if from_initiator {
                (
                    &mut p.ji,
                    &mut p.jr,
                    &p.f.initiator,
                    &p.f.responder,
                    &mut intercept_i,
                )
            } else {
                (
                    &mut p.jr,
                    &mut p.ji,
                    &p.f.responder,
                    &p.f.initiator,
                    &mut intercept_r,
                )
            };
            let mut plaintext = Zeroizing::new(vec![0; 128]);
            getrandom::fill(&mut plaintext).expect("post-disclosure application data");
            let id = sender
                .next_message_id(sc, p.session, 150)
                .expect("new epoch ID");
            assert_eq!(id.epoch().expect("epoch"), 1);
            let wire = sender
                .send_message(sc, p.session, id, &plaintext, b"application", 150)
                .expect("committed send");
            assert_eq!(
                receiver
                    .receive_message(rc, p.session, &wire, b"application", 150)
                    .expect("honest delivery")
                    .as_bytes(),
                plaintext.as_slice()
            );
            assert_eq!(
                intercept
                    .receive(&wire, b"application")
                    .expect("actual future message decryption from prior disclosure")
                    .as_bytes(),
                plaintext.as_slice()
            );
            recovered += 1;
        }
    }
    assert_eq!(recovered, 6);
    eprintln!("SEALED_RESERVATION_DISCLOSURE cut={} confirmed_epoch=1 recovered_messages={recovered} directions=2 private_input=one_snapshot", cut.stage());
}

#[test]
fn disclosed_key_reservation_exposes_traffic_computed_after_restart() {
    reservation_disclosure(Cut::KeyReserved);
}

#[test]
fn disclosed_encapsulation_reservation_exposes_traffic_computed_after_restart() {
    reservation_disclosure(Cut::EncapsulationReserved);
}
