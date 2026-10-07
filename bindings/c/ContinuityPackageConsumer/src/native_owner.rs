// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One controlled native service; registered ownership is never split or reopened.
use super::*;

struct Installed {
    service: p::DeviceService,
    signer: p::DeviceSigningKey,
}
enum Kind {
    Installed(Box<Installed>),
    Enrolled(Box<p::EnrolledDevice>),
}
pub(crate) struct NativeOwner {
    active: Option<Kind>,
}
impl NativeOwner {
    pub(crate) fn installed(service: p::DeviceService, signer: p::DeviceSigningKey) -> Self {
        Self {
            active: Some(Kind::Installed(Box::new(Installed { service, signer }))),
        }
    }
    pub(crate) fn enrolled(owner: p::EnrolledDevice) -> Self {
        Self {
            active: Some(Kind::Enrolled(Box::new(owner))),
        }
    }
    pub(crate) fn parts(&mut self) -> Result<(&mut p::DeviceService, &p::DeviceSigningKey)> {
        match self.active.as_mut().ok_or_else(|| failure(2))? {
            Kind::Installed(owner) => Ok((&mut owner.service, &owner.signer)),
            Kind::Enrolled(owner) => {
                let (service, signer, _) = owner.parts()?;
                Ok((service, signer))
            }
        }
    }
    pub(crate) fn close(&mut self) {
        if let Some(owner) = self.active.as_mut() {
            match owner {
                Kind::Installed(owner) => {
                    owner.service.close();
                    owner.signer.close();
                }
                Kind::Enrolled(owner) => owner.close(),
            }
        }
        self.active = None;
    }
}
impl Drop for NativeOwner {
    fn drop(&mut self) {
        self.close();
    }
}
