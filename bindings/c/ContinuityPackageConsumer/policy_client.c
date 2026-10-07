/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Real C invocation driver; independently issued public materials live in files. */
_Static_assert(sizeof(qpc_policy_document_v1)==104,"policy document ABI");
_Static_assert(sizeof(qpc_policy_renewal_proposal_v1)==336,"policy proposal ABI");
_Static_assert(sizeof(qpc_policy_renewal_cancellation_v1)==288,"policy cancellation ABI");
static qpc_policy_document_v1 policy_document(const char *path,uint8_t root[1985],uint8_t wire[8192]) {
    uint8_t version[8];
    enrollment_exact(path,"policy-root",root,1985);
    qpc_policy_document_v1 document={.root=root,.root_length=1985,.wire=wire};
    enrollment_exact(path,"family",document.family,32);
    enrollment_exact(path,"policy-version",version,8);
    document.version=enrollment_counter(version);
    enrollment_exact(path,"policy-digest",document.digest,32);
    document.wire_length=enrollment_read(path,"protocol-policy",wire,8192);
    return document;
}
#include "independent_policy_client.c"
static uint64_t continued_enrollment_parent(const char *path,const qpc_witness_v1 *witness,int tls) {
    uint64_t handle=enrollment_open(path,0,witness,tls);qpc_error_v1 error;
    char target_path[4096];enrollment_path(target_path,path,"continued-sdk");
    uint8_t root[1985],wire[8192];qpc_policy_document_v1 target=policy_document(target_path,root,wire);
    require(qpc_enrollment_v1_select_continued_policy(handle,(const uint8_t *)target_path,strlen(target_path),&target,&error),&error);
    require(qpc_enrollment_v1_activate_policy_continuation(handle,&error),&error);
    return handle;
}
static int policy_command(uint64_t handle,const char *path,const char *operation) {
    qpc_error_v1 error;
    if(!strcmp(operation,"enrollment-policy-witness-cancel-prepare")) {
        qpc_enrollment_status_v1 before,after;enrollment_status(handle,&before);
        qpc_policy_renewal_cancellation_v1 cancellation,again;
        uint8_t id[32],statement[32],credential[32];
        enrollment_exact(path,"credential-operation",id,32);
        enrollment_exact(path,"credential-statement",statement,32);
        enrollment_exact(path,"policy-credential-statement",credential,32);
        require(qpc_enrollment_v1_prepare_witnessed_policy_cancellation(handle,&cancellation,&error),&error);
        require(qpc_enrollment_v1_prepare_witnessed_policy_cancellation(handle,&again,&error),&error);
        if(cancellation.length!=281 || again.length!=281 || memcmp(cancellation.bytes,again.bytes,281)) fail("policy cancellation changed original reservation");
        if(memcmp(cancellation.bytes,"QPCRNC02",8) || cancellation.bytes[248]!=1 || memcmp(cancellation.bytes+136,id,32) || memcmp(cancellation.bytes+168,credential,32) || memcmp(cancellation.bytes+249,statement,32)) fail("policy cancellation identity");
        enrollment_write(path,"policy-cancellation",cancellation.bytes,cancellation.length);
        enrollment_status(handle,&after);
        if(before.phase!=after.phase || memcmp(before.signing_id,after.signing_id,32) || memcmp(before.journal,after.journal,32)) fail("policy cancellation changed registration");
        close_owner(handle);puts("policy-witness-cancellation-prepared");return 0;
    }
    char target_path[4096];enrollment_path(target_path,path,"continued-sdk");
    uint8_t target_root[1985],target_wire[8192];
    qpc_policy_document_v1 target=policy_document(target_path,target_root,target_wire);
    qpc_credential_renewal_status_v1 status;
    if(!strcmp(operation,"enrollment-policy-recover-history") || !strcmp(operation,"enrollment-policy-history-pending")) {
        uint8_t id[32],statement[32];
        enrollment_exact(path,"credential-operation",id,32);
        enrollment_exact(path,"credential-statement",statement,32);
        int32_t code=qpc_enrollment_v1_recover_historical_policy_continuation(handle,id,statement,&target,&status,&error);
        if(!strcmp(operation,"enrollment-policy-history-pending")) {
            record(code,&error);if(code!=QPC_SUSPENDED) fail("history created or abandoned an uncommitted target");
            qpc_enrollment_status_v1 registration;
            code=qpc_enrollment_v1_status(handle,&registration,&error);record(code,&error);
            if(code!=QPC_CLOSED) fail("failed history call retained native owner");
            close_owner(handle);puts("policy-history-pending");return 0;
        }
        require(code,&error);
        if(status.phase!=2) fail("historical policy recovery did not report original Committed");
        qpc_enrollment_status_v1 registration;enrollment_status(handle,&registration);
        if(registration.phase!=5) fail("historical recovery changed original enrollment phase");
        credential_status_print(&status);close_owner(handle);return 0;
    }
    int32_t selection=qpc_enrollment_v1_select_continued_policy(handle,(const uint8_t *)target_path,strlen(target_path),&target,&error);
    if(!strcmp(operation,"enrollment-policy-current-refused")) {
        record(selection,&error);if(selection!=QPC_VALIDITY) fail("expired target created current policy");
        close_owner(handle);puts("policy-expired-current-refused");return 0;
    }
    require(selection,&error);
    if(!strcmp(operation,"enrollment-policy-witness-prepare") || !strcmp(operation,"enrollment-policy-witness-carry-prepare")) {
        int carry=!strcmp(operation,"enrollment-policy-witness-carry-prepare");
        qpc_policy_renewal_proposal_v1 proposal,again;
        uint8_t id[32],statement[32];
        enrollment_exact(path,"credential-operation",id,32);
        enrollment_exact(path,"credential-statement",statement,32);
        require(qpc_enrollment_v1_prepare_witnessed_policy_continuation(handle,&proposal,&error),&error);
        require(qpc_enrollment_v1_prepare_witnessed_policy_continuation(handle,&again,&error),&error);
        if(proposal.length!=329 || again.length!=proposal.length || memcmp(proposal.bytes,again.bytes,329)) fail("policy witness preparation changed original target");
        if(memcmp(proposal.bytes,"QPCRNP02",8) || proposal.bytes[296]!=(carry ? 0 : 1) || memcmp(proposal.bytes+136,id,32) || memcmp(proposal.bytes+(carry ? 168 : 297),statement,32)) fail("policy witness proposal identity");
        if(carry) {
            uint8_t retained[32];enrollment_exact(path,"policy-retained-statement",retained,32);
            if(memcmp(proposal.bytes+297,retained,32)) fail("policy witness carry changed retained T");
        }
        enrollment_write(path,"policy-proposal",proposal.bytes,proposal.length);
        close_owner(handle);puts("policy-witness-prepared");return 0;
    } else if(!strcmp(operation,"enrollment-policy-witness-commit")) {
        uint8_t id[32],statement[32];
        enrollment_exact(path,"credential-operation",id,32);
        enrollment_exact(path,"credential-statement",statement,32);
        require(qpc_enrollment_v1_commit_witnessed_policy_continuation(handle,id,statement,&status,&error),&error);
        if(status.phase!=2) fail("policy witness commit did not retain Committed");
    } else if(!strcmp(operation,"enrollment-policy-stage") || !strcmp(operation,"enrollment-policy-carry-stage") || !strcmp(operation,"enrollment-policy-stage-conflict")) {
        uint8_t grant[65536],root[1985],id[32];
        size_t length=enrollment_read(path,"credential-renewal",grant,sizeof(grant));
        enrollment_exact(path,"credential-operation",id,32);
        qpc_account_pin_v1 pin=enrollment_pin(path,root,1);
        if(!strcmp(operation,"enrollment-policy-carry-stage")) {
            require(qpc_enrollment_v1_stage_continued_credential_renewal(handle,grant,length,&pin,id,&status,&error),&error);
        } else {
            uint8_t approvals[32768],previous_root[1985],previous_wire[8192],kind[1],previous_t[32];
            size_t approvals_length=enrollment_read(path,"policy-approvals",approvals,sizeof(approvals));
            enrollment_exact(path,"policy-predecessor-kind",kind,1);
            if(kind[0]>1) fail("policy predecessor kind");
            if(kind[0]) enrollment_exact(path,"policy-predecessor-statement",previous_t,32);
            char previous_path[4096];enrollment_path(previous_path,path,"previous-policy");
            qpc_policy_document_v1 previous=policy_document(previous_path,previous_root,previous_wire);
            int32_t code=qpc_enrollment_v1_stage_policy_continuation(handle,grant,length,&pin,id,approvals,approvals_length,&previous,kind[0] ? previous_t : NULL,&status,&error);
            if(!strcmp(operation,"enrollment-policy-stage-conflict")) {
                record(code,&error);if(code!=QPC_SCOPE_CONFLICT) fail("incorrect policy predecessor did not report Conflict");
                qpc_enrollment_status_v1 registration;
                code=qpc_enrollment_v1_status(handle,&registration,&error);record(code,&error);
                if(code!=QPC_CLOSED) fail("conflicting admitted policy stage retained owner");
                close_owner(handle);puts("policy-stage-conflict");return 0;
            }
            require(code,&error);
        }
        if(status.phase!=1) fail("policy stage did not retain Pending");
    } else if(!strcmp(operation,"enrollment-policy-reconcile")) {
        require(qpc_enrollment_v1_reconcile_policy_continuation(handle,&status,&error),&error);
        if(status.phase!=2) fail("policy reconciliation did not retain Committed");
    } else if(!strcmp(operation,"enrollment-policy-activate-missing-witness")) {
        int32_t code=qpc_enrollment_v1_activate_policy_continuation(handle,&error);
        record(code,&error);close_owner(handle);
        if(code!=QPC_ANCHOR_REQUIRED) fail("required policy activation did not refuse missing witness");
        puts("policy-required-witness-refused");return 0;
    } else if(!strcmp(operation,"enrollment-policy-activate")) {
        require(qpc_enrollment_v1_activate_policy_continuation(handle,&error),&error);
        int32_t code=qpc_enrollment_v1_credential_renewal_status(handle,&status,&error);record(code,&error);
        if(code!=QPC_OWNER_KIND) fail("continued activation did not transfer to Device");
        close_owner(handle);puts("policy-device-active");return 0;
    } else fail("unknown policy integration operation");
    credential_status_print(&status);close_owner(handle);return 0;
}
