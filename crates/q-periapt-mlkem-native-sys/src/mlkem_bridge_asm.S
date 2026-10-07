/* SPDX-License-Identifier: Apache-2.0 OR MIT */

/* Compile the vendored multilevel assembly SCU exactly once. */
#define QPN_MLKEM_BUILD_NATIVE_AARCH64
#define MLK_CONFIG_FILE "mlkem_config.h"
#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#include "mlkem_native_asm.S"
