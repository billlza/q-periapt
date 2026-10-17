/* SPDX-License-Identifier: Apache-2.0 OR MIT */

/* Fixed AVX2 arithmetic and four-way Keccak from the unchanged pinned SCU. */
#define QPN_MLKEM_BUILD_NATIVE_X86_64
#define MLK_CONFIG_FILE "mlkem_config.h"
#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#include "mlkem_native_asm.S"
