/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPN_MLKEM_CONFIG_H
#define QPN_MLKEM_CONFIG_H

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) || \
    defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) || \
    defined(MLK_CONFIG_ARITH_BACKEND_FILE) || \
    defined(MLK_CONFIG_FIPS202_BACKEND_FILE) || \
    defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER) || \
    defined(MLK_CONFIG_FIPS202X4_CUSTOM_HEADER)
#error External or native mlkem-native backends are not supported by this portable-only crate
#endif

/* Keep every upstream KEM entry point local to the single compilation unit. */
#define MLK_CONFIG_NAMESPACE_PREFIX qpn_mlkem_internal_v1_2_0_
#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static inline
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_NO_SUPERCOP

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
 * v1.2.0 declares its randomized entry points even when their definitions are
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
