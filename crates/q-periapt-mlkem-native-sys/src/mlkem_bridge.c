/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#include "mlkem_bridge.h"

/*
 * Compile all parameter sets into one portable translation unit. The upstream
 * KEM entry points and parameter-dependent helpers are `static`. The versioned
 * bridge and upstream's versioned shared FIPS 202 helpers have hidden external
 * visibility.
 */
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED

#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_keypair_derand(
    uint8_t public_key[QPN_MLKEM512_PUBLIC_KEY_BYTES],
    uint8_t decapsulation_key[QPN_MLKEM512_DECAPSULATION_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_KEYPAIR_SEED_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_512_keypair_derand(
      public_key, decapsulation_key, seed);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_encapsulate_derand(
    uint8_t ciphertext[QPN_MLKEM512_CIPHERTEXT_BYTES],
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t public_key[QPN_MLKEM512_PUBLIC_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_ENCAPSULATION_SEED_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_512_enc_derand(
      ciphertext, shared_secret, public_key, seed);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_decapsulate(
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[QPN_MLKEM512_CIPHERTEXT_BYTES],
    const uint8_t decapsulation_key[QPN_MLKEM512_DECAPSULATION_KEY_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_512_dec(
      shared_secret, ciphertext, decapsulation_key);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_check_public_key(
    const uint8_t public_key[QPN_MLKEM512_PUBLIC_KEY_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_512_check_pk(public_key);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_keypair_derand(
    uint8_t public_key[QPN_MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t decapsulation_key[QPN_MLKEM768_DECAPSULATION_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_KEYPAIR_SEED_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_768_keypair_derand(
      public_key, decapsulation_key, seed);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_encapsulate_derand(
    uint8_t ciphertext[QPN_MLKEM768_CIPHERTEXT_BYTES],
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t public_key[QPN_MLKEM768_PUBLIC_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_ENCAPSULATION_SEED_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_768_enc_derand(
      ciphertext, shared_secret, public_key, seed);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_decapsulate(
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[QPN_MLKEM768_CIPHERTEXT_BYTES],
    const uint8_t decapsulation_key[QPN_MLKEM768_DECAPSULATION_KEY_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_768_dec(
      shared_secret, ciphertext, decapsulation_key);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_check_public_key(
    const uint8_t public_key[QPN_MLKEM768_PUBLIC_KEY_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_768_check_pk(public_key);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_keypair_derand(
    uint8_t public_key[QPN_MLKEM1024_PUBLIC_KEY_BYTES],
    uint8_t decapsulation_key[QPN_MLKEM1024_DECAPSULATION_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_KEYPAIR_SEED_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_1024_keypair_derand(
      public_key, decapsulation_key, seed);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_encapsulate_derand(
    uint8_t ciphertext[QPN_MLKEM1024_CIPHERTEXT_BYTES],
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t public_key[QPN_MLKEM1024_PUBLIC_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_ENCAPSULATION_SEED_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_1024_enc_derand(
      ciphertext, shared_secret, public_key, seed);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_decapsulate(
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[QPN_MLKEM1024_CIPHERTEXT_BYTES],
    const uint8_t decapsulation_key[QPN_MLKEM1024_DECAPSULATION_KEY_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_1024_dec(
      shared_secret, ciphertext, decapsulation_key);
}

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_check_public_key(
    const uint8_t public_key[QPN_MLKEM1024_PUBLIC_KEY_BYTES])
{
  return qpn_mlkem_internal_v1_2_0_1024_check_pk(public_key);
}
