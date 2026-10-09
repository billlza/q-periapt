/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "qpc_owner.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static qpc_configuration_blob_v1 allocations[24];
static size_t allocation_count;
static void clear_allocations(void) {
    for (size_t i = 0; i < allocation_count; ++i) {
        volatile uint8_t *p = (volatile uint8_t *)allocations[i].data;
        for (size_t j = 0; j < allocations[i].length; ++j) p[j] = 0;
        free((void *)allocations[i].data);
    }
    allocation_count = 0;
}
static qpc_configuration_blob_v1 load(const char *directory, const char *name, size_t maximum) {
    qpc_configuration_blob_v1 empty = {NULL, 0};
    char path[8192];
    int n = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (n < 0 || (size_t)n >= sizeof(path) || allocation_count >= 24) return empty;
    FILE *file = fopen(path, "rb");
    if (!file) return empty;
    uint8_t *bytes = calloc(maximum + 1, 1);
    if (!bytes) { (void)fclose(file); return empty; }
    size_t length = fread(bytes, 1, maximum + 1, file);
    int failed = ferror(file);
    if (fclose(file) != 0) failed = 1;
    allocations[allocation_count++] = (qpc_configuration_blob_v1){bytes, maximum + 1};
    if (failed || length == 0 || length > maximum) return empty;
    return (qpc_configuration_blob_v1){bytes, length};
}
static int exact(qpc_configuration_blob_v1 b, size_t n) { return b.data && b.length == n; }
static uint64_t be64(const uint8_t *p) {
    uint64_t out = 0;
    for (unsigned i = 0; i < 8; ++i) out = (out << 8) | p[i];
    return out;
}
static int checked(int32_t code, const qpc_error_v1 *error) {
    if (!code) return 0;
    size_t n = error->length;
    if (n > sizeof(error->message)) n = sizeof(error->message);
    fprintf(stderr, "configuration status %d: %.*s\n", code, (int)n, (const char *)error->message);
    return 1;
}
/* Public qualification inputs are copied into the SDK before their buffers are cleared. */
static int peer_device(const char *source, const char *prefix, const uint8_t family[32], qpc_peer_device_v1 *out) {
    char name[128];
    const char *fields[] = {"root", "account", "roster-version", "roster-digest", "device", "generation"};
    const size_t sizes[] = {1985, 32, 8, 32, 16, 8};
    qpc_configuration_blob_v1 data[6];
    for (size_t i=0; i<6; ++i) {
        int n=snprintf(name,sizeof(name),"peer/%s-%s",prefix,fields[i]);
        if(n<0 || (size_t)n>=sizeof(name)) return 1;
        data[i]=load(source,name,sizes[i]); if(!exact(data[i],sizes[i])) return 1;
    }
    out->account.root=data[0].data; out->account.root_length=data[0].length;
    memcpy(out->account.account,data[1].data,32); memcpy(out->account.family,family,32);
    out->account.checkpoint.version=be64(data[2].data); memcpy(out->account.checkpoint.digest,data[3].data,32);
    memcpy(out->device,data[4].data,16); out->generation=be64(data[5].data);
    return 0;
}
static int peer_open(uint64_t parent, const char *source, const uint8_t family[32], const uint8_t *session,
                     uint64_t *peer, qpc_error_v1 *error) {
    qpc_peer_configuration_v1 input={0};
    input.header=(qpc_configuration_header_v1){sizeof(input),1}; input.quality=1; input.role=1;
    if(peer_device(source,"initiator",family,&input.initiator) || peer_device(source,"responder",family,&input.responder)) return 1;
    qpc_configuration_blob_v1 directory=load(source,"peer/directory",32);
    if(!exact(directory,32)) return 1;
    memcpy(input.directory,directory.data,32);
    input.bundle=load(source,"peer/bootstrap.bundle",65536);
    input.tls_peer=load(source,"peer/tls-peer",8192);
    input.tls_name=load(source,"peer/tls-peer-name",128);
    int32_t code=session ? qpc_peer_v1_prepare_configured_reopen(parent,&input,session,peer,error) :
        qpc_peer_v1_prepare_configured(parent,&input,peer,error);
    clear_allocations();
    return checked(code,error) || checked(qpc_owner_v1_finish_open(*peer,error),error);
}
static int traffic(uint64_t parent, const char *source, const uint8_t family[32], const char *mode,
                   uint8_t result[64], size_t *length, qpc_error_v1 *error) {
    uint64_t peer=0; int failed=1; uint8_t session[32]={0},message[32]={0},request[32]={0};
    int fresh=strcmp(mode,"connect")==0, uncertain=strcmp(mode,"uncertain-send")==0;
    qpc_configuration_blob_v1 id=load(source,fresh ? "connection-initiation" : "connection-session",32);
    if(!exact(id,32)) goto done;
    memcpy(fresh ? request : session,id.data,32);
    clear_allocations();
    if(peer_open(parent,source,family,fresh ? NULL : session,&peer,error)) goto done;
    qpc_configuration_blob_v1 address=load(source,"connection-address",128);
    if(!address.data) goto done;
    uint16_t exchanges=0;
    if(fresh) {
        if(checked(qpc_owner_v1_establish(peer,address.data,address.length,request,session,&exchanges,error),error)) goto done;
        if(!exchanges || exchanges>8) goto done;
        memcpy(result,session,32); *length=32;
    } else {
        if(uncertain) {
            if(checked(qpc_owner_v1_next_message(peer,session,message,error),error)) goto done;
        } else {
            qpc_configuration_blob_v1 original=load(source,"connection-message",32);
            if(!exact(original,32)) goto done;
            memcpy(message,original.data,32);
        }
        const uint8_t plaintext[]="first configuration payload", ad[]="configuration-v1";
        uint8_t consumption=0,status=0;
        int32_t sent=qpc_owner_v1_send(peer,address.data,address.length,session,message,
            plaintext,sizeof(plaintext)-1,ad,sizeof(ad)-1,&consumption,&exchanges,error);
        if(uncertain) {
            if((sent!=QPC_NETWORK && sent!=QPC_RETRY_EXHAUSTED && sent!=QPC_DEADLINE && sent!=QPC_TLS) || consumption) goto done;
        } else if(checked(sent,error) || consumption!=QPC_CONSUMPTION_CONFIRMED || !exchanges || exchanges>8) goto done;
        if(checked(qpc_owner_v1_message_status(peer,session,message,&status,error),error) ||
            status!=(uncertain ? QPC_MESSAGE_COMMITTED : QPC_MESSAGE_ACKNOWLEDGED)) goto done;
        memcpy(result,session,32);memcpy(result+32,message,32);*length=64;
    }
    failed=0;
done:
    clear_allocations();
    if(peer && checked(qpc_owner_v1_close(peer,error),error)) failed=1;
    return failed;
}
static int guard_pages(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 1;
    size_t length = (size_t)page * 2;
    uint8_t *memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) return 1;
    if (mprotect(memory + page, (size_t)page, PROT_NONE) != 0) { (void)munmap(memory, length); return 1; }
    qpc_configuration_header_v1 *prefix = (void *)(memory + page - sizeof(*prefix));
    prefix->struct_size = sizeof(*prefix); prefix->version = 1;
    qpc_error_v1 error = {0}; uint64_t handle = 99;
    const uint8_t path[] = "/no-configuration-from-short-header";
    int a = qpc_configuration_v1_prepare_create(path, sizeof(path)-1, (const void *)prefix, &handle, &error);
    int valid = a == QPC_ARGUMENT && handle == 0;
    handle = 99;
    int b = qpc_configuration_v1_prepare_reconcile(path, sizeof(path)-1, (const void *)prefix, &handle, &error);
    valid = valid && b == QPC_ARGUMENT && handle == 0;
    handle = 99;
    int c = qpc_configuration_v1_prepare_open(path, sizeof(path)-1, (const void *)prefix, &handle, &error);
    valid = valid && c == QPC_ARGUMENT && handle == 0;
    int d = qpc_configuration_v1_begin_enrollment(0, NULL, 2, (const void *)prefix, &error);
    valid = valid && d == QPC_ARGUMENT;
    if (munmap(memory, length) != 0) return 1;
    if (!valid) return 1;
    puts("QPC_CONFIGURATION_HEADER_GUARD_PASS");
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--guard") == 0) return guard_pages();
    if (argc != 6 && argc != 7) return 64;
    int create = strcmp(argv[1], "create") == 0;
    int prepare = strcmp(argv[1], "prepare") == 0;
    int activate = strcmp(argv[1], "activate") == 0;
    int missing = strcmp(argv[1], "activate-missing") == 0;
    int wrong = strcmp(argv[1], "wrong-witness") == 0;
    int bad_receipt = strcmp(argv[1], "activate-bad-receipt") == 0;
    int cancel = strcmp(argv[1], "cancel") == 0;
    int local = strcmp(argv[1], "enroll-local") == 0;
    int connection = strcmp(argv[1], "connect") == 0 || strcmp(argv[1], "uncertain-send") == 0 || strcmp(argv[1], "retry-send") == 0;
    if (!create && !prepare && !activate && !missing && !wrong && !bad_receipt && !cancel && !local && !connection && strcmp(argv[1], "resume") != 0) return 64;
    unsigned carrier = argc == 6 ? 0u : strcmp(argv[6], "signed") == 0 ? 1u : strcmp(argv[6], "tls") == 0 ? 2u : 3u;
    if (carrier == 3u || (missing && carrier != 0u) || (wrong && carrier == 0u)) return 64;
    int recoverable = strcmp(argv[2], "recoverable") == 0;
    if (!recoverable && strcmp(argv[2], "fixed") != 0) return 64;
    const char *source = argv[3], *target = argv[4];
    qpc_configuration_create_v1 initial = {0};
    qpc_configuration_open_v1 current = {0};
    qpc_configuration_sdk_trust_v1 sdk = {0};
    qpc_configuration_protocol_v1 protocol = {0};
    uint64_t handle = 0; qpc_error_v1 error = {0}; int result = 1;
    sdk.mode = recoverable ? 2u : 1u;
    sdk.initial_root = load(source, "sdk-root", 1952);
    if (recoverable) {
        qpc_configuration_blob_v1 scope = load(source, "recovery-scope", 32);
        if (!exact(scope, 32)) goto done;
        memcpy(sdk.scope, scope.data, 32);
        sdk.recovery_root = load(source, "recovery-root", 1952);
    }
    qpc_configuration_blob_v1 family = load(source, "family", 32);
    qpc_configuration_blob_v1 version = load(source, "policy-version", 8);
    qpc_configuration_blob_v1 digest = load(source, "policy-digest", 32);
    if (!exact(family, 32) || !exact(version, 8) || !exact(digest, 32)) goto done;
    memcpy(protocol.family, family.data, 32); memcpy(protocol.digest, digest.data, 32);
    protocol.version = be64(version.data);
    protocol.root = load(source, "policy-root", 1985);
    protocol.policy = load(source, "protocol-policy", 8192);
    if (create) {
        initial.header = (qpc_configuration_header_v1){sizeof(initial), 1};
        initial.sdk = sdk; initial.protocol = protocol;
        initial.sdk_policy = load(source, "sdk-policy", 65536);
        initial.sdk_signature = load(source, "sdk-signature", 3309);
        if (recoverable) initial.recovery_enrollment = load(source, "recovery-enrollment", 3309);
        initial.tls_certificate = load(source, "tls-cert", 8192);
        initial.tls_key = load(source, "tls-key", 8192);
        if (checked(qpc_configuration_v1_prepare_create((const uint8_t *)target, strlen(target), &initial, &handle, &error), &error)) goto done;
    } else {
        current.header = (qpc_configuration_header_v1){sizeof(current), 1};
        current.sdk = sdk; current.protocol = protocol;
        if (checked(qpc_configuration_v1_prepare_open((const uint8_t *)target, strlen(target), &current, &handle, &error), &error)) goto done;
    }
    /* Preparation copied all input bytes; no borrowed buffer remains live. */
    clear_allocations();
    if (checked(qpc_owner_v1_finish_open(handle, &error), &error)) goto done;
    qpc_configuration_blob_v1 root = load(source, "enrollment-root", 1985);
    qpc_configuration_blob_v1 intent_bytes = load(source, "enrollment-intent", 72);
    if (!exact(root, 1985) || !exact(intent_bytes, 72)) goto done;
    qpc_enrollment_intent_v1 intent = {0};
    intent.root = root.data; intent.root_length = root.length;
    memcpy(intent.device, intent_bytes.data, 16); intent.generation = be64(intent_bytes.data + 16);
    memcpy(intent.family, intent_bytes.data + 24, 32);
    intent.valid_from = be64(intent_bytes.data + 56); intent.valid_until = be64(intent_bytes.data + 64);
    qpc_configuration_witness_v1 witness = {0};
    if (carrier) {
        witness.header = (qpc_configuration_header_v1){sizeof(witness), 1};
        witness.carrier = carrier;
        qpc_configuration_blob_v1 address = load(source, "witness-address", 128);
        witness.options = (qpc_witness_v1){address.data, address.length, 3000};
        qpc_configuration_blob_v1 identity = load(source, "witness-id", 32);
        if (!exact(identity, 32)) goto done;
        memcpy(witness.identity, identity.data, 32);
        witness.public_key = load(source, "witness-public", 1985);
        if (carrier == 2) {
            witness.tls_peer = load(source, "witness-tls-peer", 8192);
            witness.tls_certificate = load(source, "witness-tls-cert", 8192);
            witness.tls_key = load(source, "witness-tls-key", 8192);
            witness.tls_name = load(source, "witness-tls-name", 128);
        }
        if (wrong) witness.identity[0] ^= 1;
    }
    if (cancel && checked(qpc_owner_v1_cancel(handle, &error), &error)) goto done;
    int32_t begun = qpc_configuration_v1_begin_enrollment(handle, &intent, create ? 1u : 2u, carrier ? &witness : NULL, &error);
    if (wrong || cancel) {
        if (begun != (cancel ? QPC_CANCELLED : QPC_SCOPE)) { (void)checked(begun, &error); goto done; }
        result = 0; goto done;
    }
    if (checked(begun, &error)) goto done;
    clear_allocations();
    qpc_enrollment_request_v1 request = {0};
    if (checked(qpc_enrollment_v1_request(handle, &request, &error), &error)) goto done;
    if (!request.length || request.length > sizeof(request.bytes)) goto done;
    uint8_t genesis[164], delivered[64];
    const uint8_t *written_bytes = request.bytes;
    size_t written_length = request.length;
    if (prepare || local) {
        qpc_configuration_blob_v1 root_again = load(source, "enrollment-root", 1985);
        qpc_configuration_blob_v1 certificate = load(source, "grant-certificate", 8192);
        qpc_configuration_blob_v1 roster = load(source, "grant-roster", 65536);
        qpc_configuration_blob_v1 account = load(source, "trusted-account", 32);
        qpc_configuration_blob_v1 roster_version = load(source, "trusted-roster-version", 8);
        qpc_configuration_blob_v1 roster_digest = load(source, "trusted-roster-digest", 32);
        if (!exact(root_again, 1985) || !exact(account, 32) || !exact(roster_version, 8) || !exact(roster_digest, 32)) goto done;
        qpc_account_pin_v1 pin = {0};
        memcpy(pin.account, account.data, 32); memcpy(pin.family, intent.family, 32);
        pin.root = root_again.data; pin.root_length = root_again.length;
        pin.checkpoint.version = be64(roster_version.data); memcpy(pin.checkpoint.digest, roster_digest.data, 32);
        uint8_t journal[32];
        if (checked(qpc_enrollment_v1_accept(handle, certificate.data, certificate.length, roster.data, roster.length, &pin, journal, &error), &error)) goto done;
        clear_allocations();
        qpc_setup_preparation_v1 prepared = {0};
        if (checked(qpc_enrollment_v1_prepare_storage(handle, &prepared, &error), &error)) goto done;
        if (prepared.protection != (local ? 1u : 2u) || memcmp(journal, prepared.journal, 32)) goto done;
        genesis[0] = 0; genesis[1] = 0; genesis[2] = 0; genesis[3] = 2;
        memcpy(genesis + 4, prepared.journal, 32); memcpy(genesis + 36, prepared.subject, 96);
        memcpy(genesis + 132, prepared.image_digest, 32);
        if (!local) { written_bytes = genesis; written_length = sizeof(genesis); }
    }
    if (activate || missing || bad_receipt || local || connection) {
        int32_t activated = qpc_enrollment_v1_activate(handle, &error);
        if (missing) {
            if (activated != QPC_ANCHOR_REQUIRED) { (void)checked(activated, &error); goto done; }
        } else if (bad_receipt) {
            if (activated != QPC_ANCHOR) { (void)checked(activated, &error); goto done; }
        } else if (checked(activated, &error)) goto done;
    }
    if (connection) {
        if (traffic(handle, source, intent.family, argv[1], delivered, &written_length, &error)) goto done;
        written_bytes = delivered;
    }
    int descriptor = open(argv[5], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) goto done;
    FILE *output = fdopen(descriptor, "wb");
    if (!output) { (void)close(descriptor); goto done; }
    size_t written = fwrite(written_bytes, 1, written_length, output);
    int closed = fclose(output);
    if (written != written_length || closed != 0) goto done;
    result = 0;
done:
    clear_allocations();
    if (handle && checked(qpc_owner_v1_close(handle, &error), &error)) result = 1;
    if (!result) puts(connection ? (strcmp(argv[1],"connect")==0 ? "QPC_CONFIGURATION_CONNECTION_PASS" :
        strcmp(argv[1],"uncertain-send")==0 ? "QPC_CONFIGURATION_UNKNOWN_COMMITTED" : "QPC_CONFIGURATION_ORIGINAL_ACKNOWLEDGED") :
        local ? "QPC_CONFIGURATION_LOCAL_ACTIVE" : cancel ? "QPC_CONFIGURATION_CANCELLED" : wrong ? "QPC_CONFIGURATION_WITNESS_SCOPE_REFUSED" :
        missing ? "QPC_CONFIGURATION_WITNESS_REQUIRED" :
        bad_receipt ? "QPC_CONFIGURATION_WITNESS_RECEIPT_REFUSED" :
        prepare ? "QPC_CONFIGURATION_GENESIS_PASS" :
        activate ? "QPC_CONFIGURATION_ACTIVATION_PASS" : "QPC_CONFIGURATION_REQUEST_PASS");
    return result;
}
