// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded fault injection for the shared native signer retirement protocol.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoStage {
    HeaderWrite,
    HeaderSync,
    Truncate,
    TerminalSync,
    DirectorySync,
}
#[derive(Clone, Copy)]
pub(crate) enum IoFault {
    Prefix(usize),
    Boundary(IoStage, bool),
    RetainedDescriptor { fail: bool },
}
struct Injection {
    fault: IoFault,
    fired: std::rc::Rc<std::cell::Cell<bool>>,
    descriptor: std::rc::Rc<std::cell::RefCell<Option<File>>>,
}
thread_local! {
    static IO_FAULT: std::cell::RefCell<Option<Injection>> = const { std::cell::RefCell::new(None) };
}
pub(crate) struct IoFaultGuard {
    fired: std::rc::Rc<std::cell::Cell<bool>>,
    descriptor: std::rc::Rc<std::cell::RefCell<Option<File>>>,
}
impl IoFaultGuard {
    pub(crate) fn fired(&self) -> bool {
        self.fired.get()
    }
    pub(crate) fn descriptor_is_held(&self) -> bool {
        self.descriptor.borrow().is_some()
    }
}
impl Drop for IoFaultGuard {
    fn drop(&mut self) {
        IO_FAULT.with(|s| {
            s.borrow_mut().take();
        });
    }
}
pub(crate) fn inject(fault: IoFault) -> IoFaultGuard {
    if let IoFault::Prefix(n) = fault {
        assert!(n <= 8);
    }
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let descriptor = std::rc::Rc::new(std::cell::RefCell::new(None));
    IO_FAULT.with(|s| {
        assert!(s.borrow().is_none());
        *s.borrow_mut() = Some(Injection {
            fault,
            fired: fired.clone(),
            descriptor: descriptor.clone(),
        });
    });
    IoFaultGuard { fired, descriptor }
}
pub(super) fn test_boundary(
    stage: IoStage,
    after: bool,
    file: &Admitted,
) -> Result<(), DurableError> {
    let cut = IO_FAULT.with(|s| {
        let mut slot = s.borrow_mut();
        let matches = slot
            .as_ref()
            .is_some_and(|injection| match injection.fault {
                IoFault::Prefix(_) => stage == IoStage::HeaderWrite && !after,
                IoFault::Boundary(at, side) => at == stage && side == after,
                IoFault::RetainedDescriptor { .. } => stage == IoStage::HeaderWrite && !after,
            });
        if matches {
            slot.take()
        } else {
            None
        }
    });
    if let Some(injection) = cut {
        injection.fired.set(true);
        if matches!(injection.fault, IoFault::RetainedDescriptor { .. }) {
            *injection.descriptor.borrow_mut() = Some(file.file.try_clone()?);
            if matches!(injection.fault, IoFault::RetainedDescriptor { fail: false }) {
                return Ok(());
            }
        }
        if let IoFault::Prefix(n) = injection.fault {
            file.backend
                .write(0, TAG.get(..n).expect("bounded injected prefix"))?;
        }
        return Err(std::io::Error::other("injected original signing-file I/O failure").into());
    }
    if let Some(root) = std::env::var_os("QPERIAPT_SIGNER_CUT_ROOT") {
        let label = format!("{stage:?}-{}", if after { "after" } else { "before" });
        if std::env::var("QPERIAPT_SIGNER_CUT_STAGE").ok().as_deref() == Some(label.as_str()) {
            use std::io::Write;
            let root = Path::new(&root);
            let mut ready =
                std::fs::File::create_new(root.join("signer-ready.pending")).expect("ready marker");
            ready.write_all(label.as_bytes()).expect("stage");
            ready.sync_all().expect("ready durable");
            std::fs::rename(root.join("signer-ready.pending"), root.join("signer-ready"))
                .expect("ready name");
            #[cfg(unix)]
            std::fs::File::open(root)
                .expect("parent")
                .sync_all()
                .expect("ready name durable");
            #[cfg(windows)]
            OwnedPrivateDirectory::open(root)
                .expect("private test parent")
                .sync_entries()
                .expect("ready name durable");
            while !root.join("signer-resume").exists() {
                std::thread::park_timeout(std::time::Duration::from_millis(10));
            }
        }
    }
    Ok(())
}
