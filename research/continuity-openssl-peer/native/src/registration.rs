// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Separate trusted fixture enrollment intent, verified before issuing a credential.
use crate::{Result, NOW};
use q_periapt_continuity_identity_candidate::{
    DeviceDescription, EnrollmentIntent, PolicySigningKey, PublicKey, RootSigningKey, SigningKeyId,
    Validity, VerifiedEnrollmentRequest,
};

pub(super) struct Pending {
    root: RootSigningKey,
    policy: PolicySigningKey,
    independent: Vec<u8>,
    intent: EnrollmentIntent,
}

pub(super) struct Approved {
    pub root: RootSigningKey,
    pub policy: PolicySigningKey,
    pub public: PublicKey,
    pub certificate: Vec<u8>,
    pub retained: Retained,
}

pub(super) struct Retained {
    intent: EnrollmentIntent,
    identity: SigningKeyId,
    public: PublicKey,
    certificate: Vec<u8>,
}

impl Pending {
    pub fn new(
        local_lifecycle: bool,
        peer_lifecycle: bool,
        extension: bool,
        policy_lifecycle: bool,
    ) -> Result<Self> {
        let root = RootSigningKey::generate()?;
        let policy = PolicySigningKey::generate()?;
        let family = policy.policy_family()?;
        let validity = Validity::new(
            100,
            if policy_lifecycle {
                450
            } else if extension {
                160
            } else if peer_lifecycle && !local_lifecycle {
                350
            } else {
                200
            },
        )?;
        let description = DeviceDescription::new([1; 16], 1, family, validity)?;
        let mut independent = root.public_key()?.encode().to_vec();
        independent.extend_from_slice(&[1; 16]);
        independent.extend_from_slice(&1u64.to_be_bytes());
        independent.extend_from_slice(&validity.from().to_be_bytes());
        independent.extend_from_slice(&validity.until().to_be_bytes());
        independent.extend_from_slice(&family);
        let intent = EnrollmentIntent::new(root.public_key()?, description);
        Ok(Self {
            root,
            policy,
            independent,
            intent,
        })
    }

    pub fn independent_intent(&self) -> &[u8] {
        &self.independent
    }

    pub fn accept(self, wire: &[u8]) -> Result<Approved> {
        let request = VerifiedEnrollmentRequest::verify(wire, &self.intent, NOW)?;
        let certificate = self.root.issue_enrollment(&request, NOW)?;
        let public = request.public_key().clone();
        let retained = Retained {
            intent: self.intent,
            identity: request.identity(),
            public: public.clone(),
            certificate: certificate.clone(),
        };
        Ok(Approved {
            root: self.root,
            policy: self.policy,
            public,
            certificate,
            retained,
        })
    }
}

impl Retained {
    pub fn retry(&self, wire: &[u8]) -> Result<Vec<u8>> {
        let request = VerifiedEnrollmentRequest::verify(wire, &self.intent, NOW)?;
        if request.identity() != self.identity || request.public_key() != &self.public {
            return Err("registration retry differs from original approved request".into());
        }
        Ok(self.certificate.clone())
    }
}
