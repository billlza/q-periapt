// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Baseline, no_std admission for the fixed AVX2 unit. No target-feature macro
//! can turn this check into compile-time true. CPU capabilities are assumed
//! uniform for the process, as for the platform's normal runtime feature cache.

use core::sync::atomic::{AtomicBool, Ordering};

const XSAVE_OSXSAVE_AVX: u32 = (1 << 26) | (1 << 27) | (1 << 28);
const AVX2: u32 = 1 << 5;
// Pinned rejection sampling uses SSSE3, SSE4.1, POPCNT and BMI2 as well.
// Feature bits are independent; do not infer them from AVX2 or a CPU brand.
const REQUIRED_LEAF1: u32 = XSAVE_OSXSAVE_AVX | (1 << 9) | (1 << 19) | (1 << 23);
const REQUIRED_LEAF7: u32 = AVX2 | (1 << 8);
const XMM_YMM_STATE: u64 = (1 << 1) | (1 << 2);

trait Probe {
    fn max_basic_leaf(&self) -> u32;
    fn leaf1_ecx(&self) -> u32;
    fn leaf7_ebx(&self) -> u32;
    // Invoked only after XSAVE/OSXSAVE have made XGETBV(0) legal.
    fn xcr0(&self) -> u64;
}

fn detect(probe: &impl Probe) -> bool {
    if probe.max_basic_leaf() < 7
        || probe.leaf1_ecx() & REQUIRED_LEAF1 != REQUIRED_LEAF1
        || probe.leaf7_ebx() & REQUIRED_LEAF7 != REQUIRED_LEAF7
    {
        return false;
    }
    probe.xcr0() & XMM_YMM_STATE == XMM_YMM_STATE
}

struct Cache {
    initialized: AtomicBool,
    usable: AtomicBool,
}
impl Cache {
    const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            usable: AtomicBool::new(false),
        }
    }
    fn get(&self, probe: &impl Probe) -> bool {
        if self.initialized.load(Ordering::Acquire) {
            return self.usable.load(Ordering::Relaxed);
        }
        let usable = detect(probe);
        self.usable.store(usable, Ordering::Relaxed);
        self.initialized.store(true, Ordering::Release);
        usable
    }
}

#[cfg(qpn_mlkem_x86_dispatch)]
struct NativeProbe;
#[cfg(qpn_mlkem_x86_dispatch)]
fn cpuid(leaf: u32) -> core::arch::x86_64::CpuidResult {
    // Older supported Rust versions expose CPUID as unsafe; newer ones make
    // it safe on x86-64. This typed coercion accepts either signature without
    // an unnecessary-unsafe warning or changing the crate's Rust version floor.
    let instruction: unsafe fn(u32, u32) -> core::arch::x86_64::CpuidResult =
        core::arch::x86_64::__cpuid_count;
    // SAFETY: the candidate is restricted to x86-64, where CPUID is baseline.
    unsafe { instruction(leaf, 0) }
}
#[cfg(qpn_mlkem_x86_dispatch)]
impl Probe for NativeProbe {
    fn max_basic_leaf(&self) -> u32 {
        cpuid(0).eax
    }
    fn leaf1_ecx(&self) -> u32 {
        cpuid(1).ecx
    }
    fn leaf7_ebx(&self) -> u32 {
        cpuid(7).ebx
    }
    fn xcr0(&self) -> u64 {
        // SAFETY: detect has observed XSAVE and OSXSAVE before this method.
        // Index 0 is the architectural XCR0 register. It never executes on a
        // path where the instruction is unavailable or disabled by the OS.
        unsafe { core::arch::x86_64::_xgetbv(0) }
    }
}

#[cfg(qpn_mlkem_x86_dispatch)]
pub(super) fn available() -> bool {
    static CPU: Cache = Cache::new();
    CPU.get(&NativeProbe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    struct Features {
        max: u32,
        leaf1: u32,
        leaf7: u32,
        xcr0: u64,
        calls: Cell<u8>,
    }
    impl Features {
        fn supported() -> Self {
            Self {
                max: 7,
                leaf1: REQUIRED_LEAF1,
                leaf7: REQUIRED_LEAF7,
                xcr0: XMM_YMM_STATE,
                calls: Cell::new(0),
            }
        }
    }
    impl Probe for Features {
        fn max_basic_leaf(&self) -> u32 {
            self.calls.set(self.calls.get() | 1);
            self.max
        }
        fn leaf1_ecx(&self) -> u32 {
            self.calls.set(self.calls.get() | 2);
            self.leaf1
        }
        fn leaf7_ebx(&self) -> u32 {
            self.calls.set(self.calls.get() | 4);
            self.leaf7
        }
        fn xcr0(&self) -> u64 {
            self.calls.set(self.calls.get() | 8);
            self.xcr0
        }
    }

    #[test]
    fn every_cpu_requirement_precedes_the_xgetbv_instruction() {
        let mut features = Features::supported();
        for max in 0..7 {
            features.max = max;
            features.calls.set(0);
            assert!(!detect(&features));
            assert_eq!(features.calls.get(), 1);
        }
        features.max = 7;
        for bit in [26, 27, 28] {
            features.leaf1 = REQUIRED_LEAF1 & !(1 << bit);
            features.calls.set(0);
            assert!(!detect(&features));
            assert_eq!(features.calls.get(), 3);
        }
        features.leaf1 = REQUIRED_LEAF1;
        features.leaf7 = 0;
        features.calls.set(0);
        assert!(!detect(&features));
        assert_eq!(features.calls.get(), 7);
    }

    #[test]
    fn every_extension_used_by_the_pinned_assembly_is_required() {
        // The actual assembly also contains pshufb, pblendw/pinsrd/pinsrq,
        // popcntq and pextq; CPUID's AVX2 bit alone does not cover them.
        let leaf1 = XSAVE_OSXSAVE_AVX | (1 << 9) | (1 << 19) | (1 << 23);
        let leaf7 = AVX2 | (1 << 8);
        for bit in [9, 19, 23] {
            let mut features = Features::supported();
            features.leaf1 = leaf1 & !(1 << bit);
            features.leaf7 = leaf7;
            assert!(!detect(&features), "missing leaf-1 feature bit {bit}");
            assert_eq!(features.calls.get() & 8, 0);
        }
        for bit in [5, 8] {
            let mut features = Features::supported();
            features.leaf1 = leaf1;
            features.leaf7 = leaf7 & !(1 << bit);
            assert!(!detect(&features), "missing leaf-7 feature bit {bit}");
            assert_eq!(features.calls.get() & 8, 0);
        }
    }

    #[test]
    fn cpu_avx2_without_both_os_register_states_is_insufficient() {
        let mut features = Features::supported();
        for xcr0 in 0..16 {
            features.xcr0 = xcr0;
            features.calls.set(0);
            assert_eq!(detect(&features), xcr0 & 6 == 6);
            assert_eq!(features.calls.get(), 15);
        }
    }

    #[test]
    fn cache_records_both_available_and_unavailable_capabilities() {
        for leaf7 in [0, REQUIRED_LEAF7] {
            let cache = Cache::new();
            let mut features = Features::supported();
            features.leaf7 = leaf7;
            assert_eq!(cache.get(&features), leaf7 != 0);
            features.calls.set(0);
            assert_eq!(cache.get(&features), leaf7 != 0);
            assert_eq!(features.calls.get(), 0);
        }
    }
}
