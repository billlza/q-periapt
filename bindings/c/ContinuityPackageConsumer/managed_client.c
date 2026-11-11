/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "qpc_owner.h"
#include "client_inputs.h"
#include <stdlib.h>
#include <string.h>

static const uint8_t payload[] = "persisted before process exit";
static const uint8_t associated[] = "owned-service";
typedef struct {
    qpc_authority_options_v1 options;
    qpc_authority_checkpoint_v1 expected;
    uint8_t witness[1985];
} registry_inputs;

static _Noreturn void fail(const char *message) {
    fprintf(stderr, "managed C failure: %s\n", message);
    exit(1);
}
static void expect(int32_t actual, int32_t wanted, const qpc_error_v1 *error) {
    if (actual != wanted || error->code != actual || error->length > sizeof error->message ||
        error->truncated > 1 || ((actual == 0) != (error->length == 0))) {
        fprintf(stderr, "managed status=%d expected=%d\n", actual, wanted);
        fail("native status or diagnostic differs");
    }
}
static void close_owner(uint64_t handle) {
    qpc_error_v1 error;
    expect(qpc_owner_v1_close(handle, &error), 0, &error);
}
static void decode(const char *text, uint8_t value[32]) {
    if (strlen(text) != 64) fail("identifier length");
    for (size_t i = 0; i < 32; ++i) {
        value[i] = 0;
        for (size_t j = 0; j < 2; ++j) {
            char ch = text[2*i+j];
            unsigned digit = ch >= '0' && ch <= '9' ? (unsigned)(ch-'0') :
                ch >= 'a' && ch <= 'f' ? (unsigned)(ch-'a')+10U : 16U;
            if (digit == 16) fail("identifier encoding");
            value[i] = (uint8_t)((unsigned)value[i]*16U+digit);
        }
    }
}
static void encode(const uint8_t value[32]) {
    for (size_t i = 0; i < 32; ++i) printf("%02x", value[i]);
    puts("");
}
static void read_registry(const char *path, registry_inputs *input) {
    input->options.struct_size = sizeof input->options;
    if (fixed(path,"registry-id",input->options.identity,32) ||
        fixed(path,"family",input->options.family,32) ||
        fixed(path,"witness-id",input->options.witness,32) ||
        fixed(path,"witness-public",input->witness,sizeof input->witness) ||
        fixed(path,"application",input->expected.application,32) ||
        fixed(path,"account",input->expected.account,32) ||
        number(path,"revision",&input->expected.revision)) fail("independent registry inputs");
    input->options.public_key = input->witness;
    input->options.public_key_length = sizeof input->witness;
}
static uint64_t open_registry(const char *path, const registry_inputs *input) {
    uint64_t handle = 0;
    qpc_error_v1 error;
    expect(qpc_authority_v1_prepare_open((const uint8_t *)path,strlen(path),
        &input->options,&handle,&error),0,&error);
    expect(qpc_owner_v1_finish_open(handle,&error),0,&error);
    return handle;
}
static uint64_t open_service(const char *path, const char *address, uint64_t registry,
                             const registry_inputs *input, const uint8_t *session, int32_t wanted) {
    qpc_witness_v1 witness = {(const uint8_t *)address,strlen(address),3000};
    qpc_open_options_v1 options = {1,1,1,&witness};
    qpc_authority_open_options_v1 selected = {
        sizeof selected,session ? 1U : 0U,registry,input->expected,&options,session
    };
    uint64_t handle = 0;
    qpc_error_v1 error;
    expect(qpc_authority_v1_prepare_owner((const uint8_t *)path,strlen(path),
        &selected,&handle,&error),0,&error);
    expect(qpc_owner_v1_finish_open(handle,&error),wanted,&error);
    if (wanted) { close_owner(handle); return 0; }
    return handle;
}
static void message_status(uint64_t owner, const uint8_t session[32], const uint8_t message[32],
                           uint8_t wanted) {
    qpc_error_v1 error;
    uint8_t status = 255;
    expect(qpc_owner_v1_message_status(owner,session,message,&status,&error),0,&error);
    if (status != wanted) fail("original message state changed");
}
static int32_t send_message(uint64_t owner, const char *peer, const uint8_t session[32],
                            const uint8_t message[32], uint8_t *consumption,
                            uint16_t *exchanges, qpc_error_v1 *error) {
    return qpc_owner_v1_send(owner,(const uint8_t *)peer,strlen(peer),session,message,
        payload,sizeof payload-1,associated,sizeof associated-1,consumption,exchanges,error);
}
static void closed_registry(const char *config, const char *registry_path, const char *witness,
                            const registry_inputs *input, uint64_t owner, uint64_t registry,
                            const uint8_t session[32], const uint8_t message[32], const char *peer) {
    qpc_error_v1 error;
    message_status(owner,session,message,QPC_MESSAGE_COMMITTED);
    close_owner(registry);
    uint64_t reopened = 0;
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        uint8_t next[32]; memset(next,99,sizeof next);
        expect(qpc_owner_v1_next_message(owner,session,next,&error),QPC_DURABLE_CLOSED,&error);
        for (size_t i=0; i<sizeof next; ++i) if (next[i]) fail("closed query returned a message identifier");
        uint8_t consumed = 99; uint16_t exchanges = 99;
        /* Send authenticates its retained archive first: preserve the documented
         * archive wrapper instead of flattening its underlying Closed status. */
        expect(send_message(owner,peer,session,message,&consumed,&exchanges,&error),1000+QPC_DURABLE_CLOSED,&error);
        if (consumed || exchanges) fail("closed registry released an outcome");
        if (!attempt) reopened = open_registry(registry_path,input);
    }
    close_owner(owner);
    owner = open_service(config,witness,reopened,input,session,0);
    message_status(owner,session,message,QPC_MESSAGE_COMMITTED);
    close_owner(owner); close_owner(reopened);
    puts("managed-closed query=202 send=1202 reopened_registry_old_owner=1202 original_status=2");
}
int main(int argc, char **argv) {
    if (argc < 6) fail("mode, original configuration, registry, witness and session/peer required");
    const char *mode=argv[1], *config=argv[2], *registry_path=argv[3], *witness=argv[4];
    int connect=!strcmp(mode,"connect"), next=!strcmp(mode,"next");
    int bad_signature=!strcmp(mode,"bad-signature"), reject=!strcmp(mode,"reject") || bad_signature;
    int rekey=!strcmp(mode,"rekey"), closed=!strcmp(mode,"closed"), uncertain=!strcmp(mode,"uncertain");
    int send=!strcmp(mode,"send");
    if (!(connect || next || reject || rekey || closed || uncertain || send) ||
        argc != (next || reject ? 6 : connect || rekey ? 7 : 8)) fail("command shape");
    registry_inputs input={0}; read_registry(registry_path,&input);
    uint64_t registry=open_registry(registry_path,&input);
    uint8_t session[32]={0}, message[32]={0};
    if (!connect) decode(argv[5],session);
    uint64_t owner=open_service(config,witness,registry,&input,connect ? NULL : session,
        reject ? (bad_signature ? QPC_ANCHOR : QPC_SCOPE_CONFLICT) : 0);
    qpc_error_v1 error;
    if (reject) {
        puts(bad_signature ? "managed-rejected:218" : "managed-rejected:211");
    } else if (connect) {
        uint8_t request[32]; uint16_t exchanges=0; decode(argv[6],request);
        expect(qpc_owner_v1_establish(owner,(const uint8_t *)argv[5],strlen(argv[5]),
            request,session,&exchanges,&error),0,&error);
        if (!exchanges || exchanges>8) fail("bootstrap exchange bound");
        encode(session);
    } else if (next) {
        expect(qpc_owner_v1_next_message(owner,session,message,&error),0,&error); encode(message);
    } else if (rekey) {
        uint64_t epoch=0;
        expect(qpc_owner_v1_rekey(owner,(const uint8_t *)argv[6],strlen(argv[6]),session,1,&epoch,&error),0,&error);
        if (epoch != 1) fail("rekey target");
        puts("managed-rekey:1");
    } else {
        decode(argv[6],message);
        if (closed) {
            closed_registry(config,registry_path,witness,&input,owner,registry,session,message,argv[7]);
            if (ferror(stdout) || fflush(stdout)) fail("output flush");
            return 0;
        }
        uint8_t consumed=0; uint16_t exchanges=0;
        int32_t code=send_message(owner,argv[7],session,message,&consumed,&exchanges,&error);
        if (uncertain) {
            if (code!=QPC_NETWORK && code!=QPC_RETRY_EXHAUSTED && code!=QPC_DEADLINE && code!=QPC_TLS)
                fail("lost receiver did not retain transport uncertainty");
            expect(code,code,&error);
            if (consumed) fail("unknown delivery reported consumed");
        } else {
            expect(code,0,&error);
            if (consumed!=QPC_CONSUMPTION_CONFIRMED || !exchanges || exchanges>8) fail("unconfirmed consumption");
        }
        message_status(owner,session,message,uncertain ? QPC_MESSAGE_COMMITTED : QPC_MESSAGE_ACKNOWLEDGED);
        puts(uncertain ? "managed-delivery-unknown:2" : "managed-consumed:3");
    }
    if (owner) close_owner(owner);
    close_owner(registry);
    if (ferror(stdout) || fflush(stdout)) fail("output flush");
    return 0;
}
