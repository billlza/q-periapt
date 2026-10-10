/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included by the first-use client: explicit host registry, never installation sidecars. */
static int select_registry(const char *path, uint64_t enrollment, uint64_t *registry,
                           qpc_error_v1 *error) {
    qpc_authority_options_v1 options = {0};
    qpc_authority_enrollment_selection_v1 selection = {0};
    const char *names[] = {"registry-id", "family", "witness-id", "witness-public",
                           "application", "account", "revision"};
    const size_t lengths[] = {32, 32, 32, 1985, 32, 32, 8};
    qpc_configuration_blob_v1 values[7];
    for (size_t i = 0; i < 7; ++i) {
        values[i] = load(path, names[i], lengths[i]);
        if (!exact(values[i], lengths[i])) return 1;
    }
    options.struct_size = sizeof options;
    memcpy(options.identity, values[0].data, 32);
    memcpy(options.family, values[1].data, 32);
    memcpy(options.witness, values[2].data, 32);
    options.public_key = values[3].data;
    options.public_key_length = values[3].length;
    selection.struct_size = sizeof selection;
    memcpy(selection.checkpoint.application, values[4].data, 32);
    memcpy(selection.checkpoint.account, values[5].data, 32);
    selection.checkpoint.revision = be64(values[6].data);
    int32_t prepared = qpc_authority_v1_prepare_open((const uint8_t *)path, strlen(path),
                                                    &options, registry, error);
    clear_allocations();
    if (checked(prepared, error) || checked(qpc_owner_v1_finish_open(*registry, error), error)) return 1;
    selection.registry = *registry;
    return checked(qpc_authority_v1_select_enrollment(enrollment, &selection, error), error);
}
