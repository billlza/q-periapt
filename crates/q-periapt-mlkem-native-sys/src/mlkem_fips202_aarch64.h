/* SPDX-License-Identifier: Apache-2.0 OR MIT */

/*
 * Keep the shipped AArch64 Keccak profile fixed per target.  The Apple
 * Silicon slices (arm64 macOS, arm64 iOS simulator) pin the Armv8.4-A SHA3
 * backends; every other owned AArch64 target pins the Armv8-A baseline.
 * The selection follows only the owned -march pin, whose agreement with the
 * target is enforced by mlkem_config.h, so each target still gets exactly
 * one fixed symbol contract with no compiler-dependent dispatch.
 *
 * This selector is intentionally re-entrant: mlkem-native's multilevel SCU
 * clears the selected upstream header guards and feature macros after each
 * parameter set, then includes the configured backend again for the next one.
 */
#if defined(__ARM_FEATURE_SHA3)
#include "src/fips202/native/aarch64/x1_v84a.h"
#include "src/fips202/native/aarch64/x2_v84a.h"
#else
#include "src/fips202/native/aarch64/x1_scalar.h"
#include "src/fips202/native/aarch64/x4_v8a_scalar.h"
#endif
