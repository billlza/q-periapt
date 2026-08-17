/* SPDX-License-Identifier: Apache-2.0 OR MIT */

/*
 * Keep the shipped AArch64 Keccak profile at the Armv8-A baseline.  Selecting
 * these two upstream headers directly avoids compiler-dependent v8.4-A/SHA3
 * dispatch and gives the C and assembly units one fixed symbol contract.
 *
 * This selector is intentionally re-entrant: mlkem-native's multilevel SCU
 * clears the selected upstream header guards and feature macros after each
 * parameter set, then includes the configured backend again for the next one.
 */
#include "src/fips202/native/aarch64/x1_scalar.h"
#include "src/fips202/native/aarch64/x4_v8a_scalar.h"
