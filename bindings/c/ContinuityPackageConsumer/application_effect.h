/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_APPLICATION_EFFECT_H
#define QPC_APPLICATION_EFFECT_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t payload[] = "persisted before process exit";
struct Application {
    uint64_t handle;
    const char *path, *mode;
    unsigned calls, created;
};
/* This test application atomically publishes effect+dedup bytes under one ID.
 * A retry compares the complete original record; it never overwrites a conflict.
 * SDK callback success follows both file and directory fsync. */
static int existing_effect(int directory, const char *name, const uint8_t *bytes, size_t length) {
    int file = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file < 0) return errno == ENOENT ? 1 : -1;
    struct stat info;
    uint8_t observed[64 + sizeof(payload)];
    size_t used = 0;
    int bad = fstat(file, &info) || !S_ISREG(info.st_mode) || info.st_size != (off_t)length;
    while (!bad && used < sizeof(observed)) {
        ssize_t count = read(file, observed + used, sizeof(observed) - used);
        if (count < 0) { if (errno == EINTR) continue; bad = 1; break; }
        if (!count) break;
        used += (size_t)count;
    }
    if (!bad && (used != length || memcmp(observed, bytes, length))) bad = 1;
    if (!bad && fsync(file)) bad = 1;
    if (close(file)) bad = 1;
    if (!bad && fsync(directory)) bad = 1;
    return bad ? -1 : 0;
}
static int persist_effect(struct Application *app, const uint8_t session[32],
                          const uint8_t message[32], const uint8_t *plaintext, size_t length) {
    if (length != sizeof(payload)-1 || memcmp(plaintext, payload, length)) return -1;
    uint8_t bytes[64 + sizeof(payload)-1];
    memcpy(bytes, session, 32); memcpy(bytes+32, message, 32); memcpy(bytes+64, plaintext, length);
    char name[sizeof("application-") + 64], temporary[sizeof(name) + 64];
    memcpy(name, "application-", sizeof("application-")-1);
    for (size_t i = 0; i < 32; ++i) {
        int n = snprintf(name + sizeof("application-")-1 + i*2, 3, "%02x", message[i]);
        if (n != 2) return -1;
    }
    int n = snprintf(temporary, sizeof(temporary), ".%s.%ld.tmp", name, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(temporary)) return -1;
    int directory = open(app->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return -1;
    int found = existing_effect(directory, name, bytes, sizeof(bytes));
    if (found != 1) { if (close(directory)) return -1; return found; }
    int file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (file < 0) { if (close(directory)) return -1; return -1; }
    int bad = 0;
    size_t used = 0;
    while (used < sizeof(bytes)) {
        ssize_t count = write(file, bytes+used, sizeof(bytes)-used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { bad = 1; break; }
        used += (size_t)count;
    }
    if (!bad && fsync(file)) bad = 1;
    if (close(file)) bad = 1;
    if (!bad) {
        if (linkat(directory, temporary, directory, name, 0) == 0) app->created++;
        else if (errno != EEXIST) bad = 1;
    }
    if (unlinkat(directory, temporary, 0)) bad = 1;
    if (!bad && existing_effect(directory, name, bytes, sizeof(bytes)) != 0) bad = 1;
    if (close(directory)) bad = 1;
    return bad ? -1 : 0;
}
#endif
