/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPN_MLKEM_CONFIG_H
#define QPN_MLKEM_CONFIG_H

/* Exactly one source wrapper owns the implementation selection. */
#if (defined(QPN_MLKEM_BUILD_NATIVE_AARCH64) + \
     defined(QPN_MLKEM_BUILD_PORTABLE) + \
     defined(QPN_MLKEM_BUILD_NATIVE_X86_64)) != 1
#error Exactly one owned mlkem-native implementation selector is required
#endif

/* Reject caller-supplied upstream backend selection before defining ours. */
#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) || \
    defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) || \
    defined(MLK_CONFIG_ARITH_BACKEND_FILE) || \
    defined(MLK_CONFIG_FIPS202_BACKEND_FILE) || \
    defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER) || \
    defined(MLK_CONFIG_FIPS202X4_CUSTOM_HEADER)
#error External mlkem-native backend configuration is not supported
#endif

/* Keep every upstream KEM entry point local to the single compilation unit. */
#if defined(QPN_MLKEM_BUILD_NATIVE_X86_64)
#define MLK_CONFIG_NAMESPACE_PREFIX qpn_mlkem_internal_v2_0_0_avx2_
#else
#define MLK_CONFIG_NAMESPACE_PREFIX qpn_mlkem_internal_v2_0_0_
#endif
#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static inline
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static

#if defined(QPN_MLKEM_BUILD_NATIVE_AARCH64)
#if defined(QPN_MLKEM_FREESTANDING) || defined(MLK_CONFIG_NO_ASM)
#error The owned AArch64 backend cannot be combined with a freestanding build
#endif
#if !defined(__AARCH64EL__) || defined(__AARCH64EB__)
#error The owned AArch64 backend requires little-endian AArch64 compiler metadata
#endif
/*
 * Each owned AArch64 FIPS 202 profile is fixed per target: arm64 macOS and
 * the arm64 iOS simulator execute only on Apple Silicon hosts (FEAT_SHA3
 * guaranteed) and must compile the Armv8.4-A SHA3 profile, while the iOS
 * device slice, Android, and generic Linux support CPUs without the SHA3
 * extension and must compile the Armv8-A baseline profile. A mismatch here
 * means the compiler driver drifted from the owned -march pin.
 */
#if defined(__APPLE__)
#include <TargetConditionals.h>
#if TARGET_OS_OSX || TARGET_OS_SIMULATOR
#if !defined(__ARM_FEATURE_SHA3)
#error The owned Apple Silicon slices require the fixed Armv8.4-A SHA3 FIPS 202 profile
#endif
#else
#if defined(__ARM_FEATURE_SHA3)
#error The owned Apple device slice requires the fixed Armv8-A FIPS 202 profile
#endif
#endif
#else
#if defined(__ARM_FEATURE_SHA3)
#error The owned Linux and Android targets require the fixed Armv8-A FIPS 202 profile
#endif
#endif
#if !defined(__APPLE__) && !defined(__linux__)
#error The owned AArch64 backend is restricted to Apple, Linux, and Android targets
#endif
#define MLK_FORCE_AARCH64
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_ARITH_BACKEND_FILE "native/meta.h"
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_FIPS202_BACKEND_FILE "mlkem_fips202_aarch64.h"
#endif /* QPN_MLKEM_BUILD_NATIVE_AARCH64 */

#if defined(QPN_MLKEM_BUILD_NATIVE_X86_64)
#if !defined(__x86_64__) || !defined(__linux__) || defined(__ANDROID__) || \
    defined(_WIN32) || defined(__APPLE__)
#error The owned AVX2 candidate is restricted to Linux x86_64 SysV
#endif
#if defined(QPN_MLKEM_FREESTANDING) || defined(MLK_CONFIG_NO_ASM)
#error The owned AVX2 candidate requires its assembly unit
#endif
#if defined(__AVX__) || defined(__AVX2__)
#error Compile the candidate C unit for baseline x86-64, not with global AVX flags
#endif
/* The Rust raw boundary admits this fixed AVX2 unit only after checking
 * CPUID (AVX2, BMI2, POPCNT, SSSE3, SSE4.1, AVX, XSAVE, OSXSAVE) and
 * XGETBV's XMM/YMM state bits. C stays
 * baseline; only these separately assembled upstream functions use AVX2.
 * Direct backend selectors avoid upstream's compile-time __AVX2__ selector.
 * The portable unit has a distinct namespace and is always linked as well. */
#define MLK_FORCE_X86_64
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_ARITH_BACKEND_FILE "native/x86_64/meta.h"
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_FIPS202_BACKEND_FILE "fips202/native/x86_64/keccak_f1600_x4_avx2.h"
#endif /* QPN_MLKEM_BUILD_NATIVE_X86_64 */

#if defined(QPN_MLKEM_FREESTANDING)
/*
 * Define the complete freestanding contract before the first src/sys.h
 * inclusion. The bridge's constants-only public-header include loads this
 * configuration before the SCU, so a later definition would be defeated by
 * both the configuration and sys.h include guards.
 */
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_MEMCPY
#define MLK_CONFIG_CUSTOM_MEMSET
#define MLK_CONFIG_CUSTOM_ZEROIZE
#endif /* QPN_MLKEM_FREESTANDING */

/*
 * v2.0.0 declares its randomized entry points even when their definitions are
 * disabled. With static linkage GCC correctly diagnoses those declarations as
 * never defined. Keep the unreachable static-inline definitions well-formed,
 * but provide no entropy source and expose no bridge for them.
 */
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>
#include "src/sys.h"

static MLK_INLINE int mlk_randombytes(uint8_t *output, size_t length)
{
  size_t index;
  for (index = 0; index < length; index++)
  {
    output[index] = 0;
  }
  return -1;
}
#endif /* !__ASSEMBLER__ */

#if defined(QPN_MLKEM_FREESTANDING)
#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>
#include "src/sys.h"

static MLK_INLINE void *mlk_memcpy(void *destination, const void *source,
                                   size_t length)
{
  size_t index;
  uint8_t *destination_bytes = (uint8_t *)destination;
  const uint8_t *source_bytes = (const uint8_t *)source;
  for (index = 0; index < length; index++)
  {
    destination_bytes[index] = source_bytes[index];
  }
  return destination;
}

static MLK_INLINE void *mlk_memset(void *destination, int value, size_t length)
{
  size_t index;
  uint8_t *destination_bytes = (uint8_t *)destination;
  for (index = 0; index < length; index++)
  {
    destination_bytes[index] = (uint8_t)value;
  }
  return destination;
}

static MLK_INLINE void mlk_zeroize(void *destination, size_t length)
{
  size_t index;
  volatile uint8_t *destination_bytes = (volatile uint8_t *)destination;
  for (index = 0; index < length; index++)
  {
    destination_bytes[index] = 0;
  }
}
#endif /* !__ASSEMBLER__ */
#endif /* QPN_MLKEM_FREESTANDING */

#endif /* QPN_MLKEM_CONFIG_H */
