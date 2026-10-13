// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Private platform storage ownership used by the shared lifecycle drivers.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use native::Storage;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod browser;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use browser::Storage;
