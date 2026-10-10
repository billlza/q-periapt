/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "qpc_owner.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    qpc_authority_options_v1 registry;
    qpc_account_pin_v1 pin;
    qpc_authority_association_v1 association;
    uint8_t witness[8192], root[8192], certificate[8192], roster[8192];
    uint64_t from, until;
} inputs;

static int load(const char *directory, const char *name, uint8_t *out,
                size_t maximum, size_t *length) {
    char path[4096];
    int n = snprintf(path, sizeof path, "%s/%s", directory, name);
    if (n < 0 || (size_t)n >= sizeof path) return 1;
    FILE *file = fopen(path, "rb");
    if (!file) return 1;
    *length = fread(out, 1, maximum, file);
    int extra = fgetc(file), failed = ferror(file) || !*length || extra != EOF;
    return fclose(file) || failed;
}
static int fixed(const char *directory, const char *name, uint8_t *out, size_t length) {
    size_t actual = 0;
    return load(directory, name, out, length, &actual) || actual != length;
}
static int number(const char *directory, const char *name, uint64_t *out) {
    uint8_t bytes[8];
    if (fixed(directory, name, bytes, sizeof bytes)) return 1;
    *out = 0;
    for (size_t i = 0; i < sizeof bytes; i++) *out = (*out << 8) | bytes[i];
    return 0;
}
static int read_inputs(const char *path, inputs *in) {
    in->registry.struct_size = sizeof in->registry;
    in->association.struct_size = sizeof in->association;
    if (fixed(path, "registry-id", in->registry.identity, 32) ||
        fixed(path, "family", in->registry.family, 32) ||
        fixed(path, "witness-id", in->registry.witness, 32) ||
        load(path, "witness-public", in->witness, sizeof in->witness, &in->registry.public_key_length) ||
        fixed(path, "application", in->association.application, 32) ||
        fixed(path, "account", in->pin.account, 32) ||
        load(path, "root-public", in->root, sizeof in->root, &in->pin.root_length) ||
        load(path, "certificate", in->certificate, sizeof in->certificate, &in->association.certificate_length) ||
        load(path, "roster", in->roster, sizeof in->roster, &in->association.roster_length) ||
        number(path, "roster-version", &in->pin.checkpoint.version) ||
        fixed(path, "roster-digest", in->pin.checkpoint.digest, 32) ||
        number(path, "valid-from", &in->from) || number(path, "valid-until", &in->until)) return 1;
    in->registry.public_key = in->witness;
    in->pin.root = in->root;
    memcpy(in->pin.family, in->registry.family, 32);
    in->association.pin = &in->pin;
    in->association.certificate = in->certificate;
    in->association.roster = in->roster;
    return 0;
}
static int checked(int32_t code, const qpc_error_v1 *error) {
    if (!code) return 0;
    fprintf(stderr, "authority C call failed code=%d diagnostic=%d\n", code, error->code);
    return 1;
}
static int close_owner(uint64_t *handle, qpc_error_v1 *error) {
    if (!*handle) return 0;
    int failed = checked(qpc_owner_v1_close(*handle, error), error);
    if (!failed) *handle = 0;
    return failed;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    inputs *in = calloc(1, sizeof *in);
    if (!in) return 3;
    qpc_error_v1 error = {0};
    uint64_t registry = 0, child = 0;
    qpc_authority_checkpoint_v1 original = {0}, observed = {0};
    const uint8_t *path = (const uint8_t *)argv[2], *enrollment = (const uint8_t *)argv[3];
    int failed = 1;
    if (read_inputs(argv[1], in)) goto done;
    _Alignas(qpc_authority_options_v1) uint32_t short_header = sizeof short_header;
    if (qpc_authority_v1_prepare_create(path, strlen(argv[2]),
        (const qpc_authority_options_v1 *)&short_header, &registry, &error) != QPC_ARGUMENT || registry) goto done;
    if (checked(qpc_authority_v1_provision_wrapping_key(path, strlen(argv[2]), &error), &error) ||
        checked(qpc_authority_v1_prepare_create(path, strlen(argv[2]), &in->registry, &registry, &error), &error)) goto done;
    /* Preparation must have copied the caller's original public key. */
    in->witness[0] ^= 0x80;
    int32_t opened = qpc_owner_v1_finish_open(registry, &error);
    in->witness[0] ^= 0x80;
    if (checked(opened, &error) ||
        checked(qpc_authority_v1_associate(registry, &in->association, &original, &error), &error)) goto done;
    if (original.revision != 1 || memcmp(original.account, in->pin.account, 32) ||
        memcmp(original.application, in->association.application, 32)) goto done;
    qpc_enrollment_intent_v1 intent = {0};
    intent.root = in->root; intent.root_length = in->pin.root_length;
    memset(intent.device, 31, sizeof intent.device); intent.generation = 1;
    memcpy(intent.family, in->pin.family, sizeof intent.family);
    intent.valid_from = in->from; intent.valid_until = in->until;
    const uint8_t address[] = "127.0.0.1:9";
    qpc_witness_v1 witness = {address, sizeof address - 1, 1000};
    qpc_open_options_v1 options = {3, 0, 1, &witness};
    qpc_authority_enrollment_options_v1 selected = {
        sizeof selected, 1, registry, original, &intent, &options
    };
    if (checked(qpc_authority_v1_prepare_enrollment(enrollment, strlen(argv[3]), &selected, &child, &error), &error) ||
        close_owner(&registry, &error)) goto done;
    if (qpc_owner_v1_finish_open(child, &error) != QPC_DURABLE_CLOSED || close_owner(&child, &error)) goto done;
    char absent[4096];
    int n = snprintf(absent, sizeof absent, "%s/enrollment.redb", argv[3]);
    struct stat entry;
    if (n < 0 || (size_t)n >= sizeof absent || stat(absent, &entry) != -1 || errno != ENOENT) goto done;
    if (checked(qpc_authority_v1_prepare_open(path, strlen(argv[2]), &in->registry, &registry, &error), &error) ||
        checked(qpc_owner_v1_finish_open(registry, &error), &error) ||
        checked(qpc_authority_v1_checkpoint(registry, original.application, &observed, &error), &error)) goto done;
    if (observed.revision != original.revision || memcmp(observed.account, original.account, 32) ||
        memcmp(observed.application, original.application, 32)) goto done;
    selected.registry = registry;
    if (checked(qpc_enrollment_v1_provision_wrapping_key(enrollment, strlen(argv[3]), &error), &error) ||
        checked(qpc_authority_v1_prepare_enrollment(enrollment, strlen(argv[3]), &selected, &child, &error), &error) ||
        checked(qpc_owner_v1_finish_open(child, &error), &error)) goto done;
    if (close_owner(&registry, &error) || close_owner(&child, &error)) goto done;
    puts("AUTHORITY_C_OWNER exact_mapping=true snapshot=true short_header=true pending_closed=202 same_registry_reopen=true managed_enrollment_constructed=true traffic_qualified=false");
    failed = 0;
done:
    {
        int child_failed = close_owner(&child, &error);
        int registry_failed = close_owner(&registry, &error);
        if (child_failed || registry_failed) failed = 1;
    }
    free(in);
    return failed;
}
