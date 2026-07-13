/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPN_MLKEM_BRIDGE_H
#define QPN_MLKEM_BRIDGE_H

#include <stdint.h>

#define MLK_CONFIG_API_CONSTANTS_ONLY
#include "mlkem_native.h"
#undef MLK_CONFIG_API_CONSTANTS_ONLY

#if MLKEM512_PUBLICKEYBYTES != 800 || MLKEM512_SECRETKEYBYTES != 1632 || \
    MLKEM512_CIPHERTEXTBYTES != 768 || MLKEM768_PUBLICKEYBYTES != 1184 || \
    MLKEM768_SECRETKEYBYTES != 2400 || MLKEM768_CIPHERTEXTBYTES != 1088 || \
    MLKEM1024_PUBLICKEYBYTES != 1568 || MLKEM1024_SECRETKEYBYTES != 3168 || \
    MLKEM1024_CIPHERTEXTBYTES != 1568 || MLKEM_SYMBYTES != 32 || \
    MLKEM_BYTES != 32
#error Q-Periapt ML-KEM bridge lengths do not match the pinned upstream header
#endif

enum
{
  QPN_MLKEM_KEYPAIR_SEED_BYTES = 2 * MLKEM_SYMBYTES,
  QPN_MLKEM_ENCAPSULATION_SEED_BYTES = MLKEM_SYMBYTES,
  QPN_MLKEM_SHARED_SECRET_BYTES = MLKEM_BYTES,
  QPN_MLKEM512_PUBLIC_KEY_BYTES = MLKEM512_PUBLICKEYBYTES,
  QPN_MLKEM512_DECAPSULATION_KEY_BYTES = MLKEM512_SECRETKEYBYTES,
  QPN_MLKEM512_CIPHERTEXT_BYTES = MLKEM512_CIPHERTEXTBYTES,
  QPN_MLKEM768_PUBLIC_KEY_BYTES = MLKEM768_PUBLICKEYBYTES,
  QPN_MLKEM768_DECAPSULATION_KEY_BYTES = MLKEM768_SECRETKEYBYTES,
  QPN_MLKEM768_CIPHERTEXT_BYTES = MLKEM768_CIPHERTEXTBYTES,
  QPN_MLKEM1024_PUBLIC_KEY_BYTES = MLKEM1024_PUBLICKEYBYTES,
  QPN_MLKEM1024_DECAPSULATION_KEY_BYTES = MLKEM1024_SECRETKEYBYTES,
  QPN_MLKEM1024_CIPHERTEXT_BYTES = MLKEM1024_CIPHERTEXTBYTES
};

#if defined(__GNUC__) || defined(__clang__)
#define QPN_MLKEM_BRIDGE_HIDDEN __attribute__((visibility("hidden")))
#define QPN_MLKEM_BRIDGE_MUST_CHECK __attribute__((warn_unused_result))
#else
#define QPN_MLKEM_BRIDGE_HIDDEN
#define QPN_MLKEM_BRIDGE_MUST_CHECK
#endif

#define QPN_MLKEM_BRIDGE_API \
  QPN_MLKEM_BRIDGE_HIDDEN QPN_MLKEM_BRIDGE_MUST_CHECK

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_keypair_derand(
    uint8_t public_key[QPN_MLKEM512_PUBLIC_KEY_BYTES],
    uint8_t decapsulation_key[QPN_MLKEM512_DECAPSULATION_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_KEYPAIR_SEED_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_encapsulate_derand(
    uint8_t ciphertext[QPN_MLKEM512_CIPHERTEXT_BYTES],
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t public_key[QPN_MLKEM512_PUBLIC_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_ENCAPSULATION_SEED_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_decapsulate(
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[QPN_MLKEM512_CIPHERTEXT_BYTES],
    const uint8_t decapsulation_key[QPN_MLKEM512_DECAPSULATION_KEY_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_512_check_public_key(
    const uint8_t public_key[QPN_MLKEM512_PUBLIC_KEY_BYTES]);

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_keypair_derand(
    uint8_t public_key[QPN_MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t decapsulation_key[QPN_MLKEM768_DECAPSULATION_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_KEYPAIR_SEED_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_encapsulate_derand(
    uint8_t ciphertext[QPN_MLKEM768_CIPHERTEXT_BYTES],
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t public_key[QPN_MLKEM768_PUBLIC_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_ENCAPSULATION_SEED_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_decapsulate(
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[QPN_MLKEM768_CIPHERTEXT_BYTES],
    const uint8_t decapsulation_key[QPN_MLKEM768_DECAPSULATION_KEY_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_768_check_public_key(
    const uint8_t public_key[QPN_MLKEM768_PUBLIC_KEY_BYTES]);

QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_keypair_derand(
    uint8_t public_key[QPN_MLKEM1024_PUBLIC_KEY_BYTES],
    uint8_t decapsulation_key[QPN_MLKEM1024_DECAPSULATION_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_KEYPAIR_SEED_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_encapsulate_derand(
    uint8_t ciphertext[QPN_MLKEM1024_CIPHERTEXT_BYTES],
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t public_key[QPN_MLKEM1024_PUBLIC_KEY_BYTES],
    const uint8_t seed[QPN_MLKEM_ENCAPSULATION_SEED_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_decapsulate(
    uint8_t shared_secret[QPN_MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[QPN_MLKEM1024_CIPHERTEXT_BYTES],
    const uint8_t decapsulation_key[QPN_MLKEM1024_DECAPSULATION_KEY_BYTES]);
QPN_MLKEM_BRIDGE_API int qpn_mlkem_bridge_v1_2_0_1024_check_public_key(
    const uint8_t public_key[QPN_MLKEM1024_PUBLIC_KEY_BYTES]);

#endif /* QPN_MLKEM_BRIDGE_H */
