/* SPDX-License-Identifier: Apache-2.0 OR MIT */

/* A separate fixed AVX2 implementation, entered only by the checked Rust
 * dispatcher. Do not compile this C unit with -mavx2 or -march=native. */
#define QPN_MLKEM_BUILD_NATIVE_X86_64
#define MLK_CONFIG_FILE "mlkem_config.h"
#include "mlkem_bridge.c"
