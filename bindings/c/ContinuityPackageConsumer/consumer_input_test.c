/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Include stdio first, as a normal C11 consumer may do. No POSIX feature macro. */
#include <stdio.h>
#include "consumer_input.h"
#include <string.h>

int main(void) {
    const char body[] = "original input bytes";
    char observed[sizeof body] = {0};
    FILE *file = tmpfile();
    if (!file) return 1;
    int failed = 1;
    if (fwrite(body, 1, sizeof body, file) != sizeof body ||
        qpc_input_seek(file, 0, SEEK_END) ||
        qpc_input_position(file) != (int64_t)sizeof body ||
        qpc_input_seek(file, -(int64_t)sizeof body, SEEK_CUR) ||
        qpc_input_position(file) != 0 ||
        fread(observed, 1, sizeof observed, file) != sizeof observed ||
        memcmp(observed, body, sizeof body) ||
        qpc_input_seek(file, 1, SEEK_SET) || qpc_input_position(file) != 1) goto done;
    failed = 0;
done:
    if (fclose(file)) failed = 1;
    if (!failed) puts("CONSUMER_INPUT_PASS c11=true seek_set_cur_end=true exact_position=true original_bytes=true");
    return failed;
}
