/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* First-use composition uses only explicit host inputs and public owner calls. */
static int select_policy_target(uint64_t enrollment, const char *source, const char *path,
                                int recoverable, qpc_error_v1 *error) {
    char inputs[8192], target[8192];
    int a=snprintf(inputs,sizeof(inputs),"%s/policy-target",source);
    int b=snprintf(target,sizeof(target),"%s.policy-target",path);
    if(a<0 || (size_t)a>=sizeof(inputs) || b<0 || (size_t)b>=sizeof(target)) return 1;
    qpc_configuration_open_v1 current={0};
    current.header=(qpc_configuration_header_v1){sizeof(current),1};
    current.sdk.mode=recoverable ? 2u : 1u;
    current.sdk.initial_root=load(inputs,"sdk-root",1952);
    if(recoverable) {
        qpc_configuration_blob_v1 scope=load(inputs,"recovery-scope",32);
        if(!exact(scope,32)) return 1;
        memcpy(current.sdk.scope,scope.data,32);
        current.sdk.recovery_root=load(inputs,"recovery-root",1952);
    }
    qpc_configuration_blob_v1 family=load(inputs,"family",32),version=load(inputs,"policy-version",8),digest=load(inputs,"policy-digest",32);
    if(!exact(family,32) || !exact(version,8) || !exact(digest,32)) return 1;
    memcpy(current.protocol.family,family.data,32); memcpy(current.protocol.digest,digest.data,32);
    current.protocol.version=be64(version.data);
    current.protocol.root=load(inputs,"policy-root",1985);
    current.protocol.policy=load(inputs,"protocol-policy",8192);
    uint64_t handle=0;
    int failed=checked(qpc_configuration_v1_prepare_open((const uint8_t *)target,strlen(target),&current,&handle,error),error);
    clear_allocations();
    if(!failed) failed=checked(qpc_owner_v1_finish_open(handle,error),error);
    if(!failed) failed=checked(qpc_configuration_v1_select_continued_policy(handle,enrollment,error),error);
    if(handle && checked(qpc_owner_v1_close(handle,error),error)) failed=1;
    return failed;
}
static int policy_document_explicit(const char *source, qpc_policy_document_v1 *document) {
    qpc_configuration_blob_v1 family=load(source,"family",32),version=load(source,"policy-version",8),digest=load(source,"policy-digest",32);
    if(!exact(family,32) || !exact(version,8) || !exact(digest,32)) return 1;
    qpc_configuration_blob_v1 root=load(source,"policy-root",1985),wire=load(source,"protocol-policy",8192);
    if(!exact(root,1985) || !wire.data) return 1;
    document->root=root.data; document->root_length=root.length;
    memcpy(document->family,family.data,32); document->version=be64(version.data); memcpy(document->digest,digest.data,32);
    document->wire=wire.data; document->wire_length=wire.length;
    return 0;
}
static int policy_operation(uint64_t enrollment,const char *source,const char *path,int recoverable,
                            unsigned carrier,const char *mode,uint8_t *output,size_t *length,qpc_error_v1 *error) {
    if(!strcmp(mode,"policy-request")) {
        qpc_configuration_blob_v1 operation=load(source,"renewal-operation",32);
        if(!exact(operation,32)) return 1;
        qpc_policy_renewal_request_v1 request={0};
        int32_t code=carrier ? qpc_enrollment_v1_witnessed_policy_renewal_request(enrollment,operation.data,&request,error) :
            qpc_enrollment_v1_policy_renewal_request(enrollment,operation.data,&request,error);
        if(checked(code,error)) return 1;
        memcpy(output,&request,sizeof(request)); *length=sizeof(request); return 0;
    }
    if(!strcmp(mode,"policy-witness-recover")) {
        qpc_independent_policy_preparation_v1 recovered={0};
        if(checked(qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation(enrollment,&recovered,error),error)) return 1;
        if(recovered.present!=1 || recovered.reserved) return 1;
        memcpy(output,recovered.proposal.bytes,sizeof(recovered.proposal.bytes)); *length=sizeof(recovered.proposal.bytes); return 0;
    }
    if(!strcmp(mode,"policy-witness-commit") || !strcmp(mode,"policy-witness-reconcile")) {
        if(!strcmp(mode,"policy-witness-commit") && select_policy_target(enrollment,source,path,recoverable,error)) return 1;
        qpc_configuration_blob_v1 raw=load(source,"renewal-proposal",296);
        if(!exact(raw,296)) return 1;
        qpc_independent_policy_proposal_v1 proposal; memcpy(proposal.bytes,raw.data,296);
        uint32_t state=0;
        int32_t code=!strcmp(mode,"policy-witness-commit") ? qpc_enrollment_v1_commit_witnessed_policy_renewal(enrollment,&proposal,&state,error) :
            qpc_enrollment_v1_reconcile_witnessed_policy_renewal(enrollment,&proposal,&state,error);
        if(checked(code,error)) return 1;
        memcpy(output,&state,sizeof(state)); *length=sizeof(state); return 0;
    }
    if(select_policy_target(enrollment,source,path,recoverable,error)) return 1;
    if(!strcmp(mode,"policy-witness-prepare")) {
        qpc_policy_document_v1 previous={0};
        if(policy_document_explicit(source,&previous)) return 1;
        qpc_independent_policy_proposal_v1 proposal={0};
        if(checked(qpc_enrollment_v1_prepare_witnessed_policy_renewal(enrollment,&previous,&proposal,error),error)) return 1;
        memcpy(output,proposal.bytes,sizeof(proposal.bytes)); *length=sizeof(proposal.bytes); return 0;
    }
    qpc_policy_renewal_status_v1 status={0};
    if(!strcmp(mode,"policy-reconcile")) {
        if(checked(qpc_enrollment_v1_reconcile_policy_renewal(enrollment,&status,error),error)) return 1;
    } else if(!strcmp(mode,"policy-stage") || !strcmp(mode,"policy-stage-refused")) {
        qpc_configuration_blob_v1 raw=load(source,"renewal-request",sizeof(qpc_policy_renewal_request_v1));
        if(!exact(raw,sizeof(qpc_policy_renewal_request_v1))) return 1;
        qpc_policy_renewal_request_v1 request; memcpy(&request,raw.data,sizeof(request));
        clear_allocations();
        qpc_configuration_blob_v1 root=load(source,"enrollment-root",1985),account=load(source,"trusted-account",32);
        qpc_configuration_blob_v1 version=load(source,"trusted-roster-version",8),digest=load(source,"trusted-roster-digest",32),family=load(source,"family",32);
        if(!exact(root,1985) || !exact(account,32) || !exact(version,8) || !exact(digest,32) || !exact(family,32)) return 1;
        qpc_account_pin_v1 pin={0}; pin.root=root.data; pin.root_length=root.length;
        memcpy(pin.account,account.data,32); memcpy(pin.family,family.data,32);
        pin.checkpoint.version=be64(version.data); memcpy(pin.checkpoint.digest,digest.data,32);
        qpc_configuration_blob_v1 approvals=load(source,"renewal-approvals",8192);
        qpc_policy_document_v1 previous={0};
        if(!approvals.data || policy_document_explicit(source,&previous)) return 1;
        uint8_t signed_bytes[8192]; memcpy(signed_bytes,approvals.data,approvals.length);
        int refused=!strcmp(mode,"policy-stage-refused");
        if(refused) signed_bytes[approvals.length-1]^=1;
        memset(&status,0xa5,sizeof(status));
        int32_t staged=qpc_enrollment_v1_stage_policy_renewal(enrollment,&request,&pin,&pin,signed_bytes,approvals.length,&previous,&status,error);
        if(refused) {
            if(staged!=QPC_AUTHENTICATION) { (void)checked(staged,error); return 1; }
            const uint8_t *untouched=(const uint8_t *)&status;
            for(size_t i=0;i<sizeof(status);++i) if(untouched[i]!=0xa5) return 1;
            qpc_enrollment_status_v1 original={0};
            if(qpc_enrollment_v1_status(enrollment,&original,error)!=QPC_CLOSED) return 1;
            uint32_t reason=QPC_AUTHENTICATION; memcpy(output,&reason,sizeof(reason)); *length=sizeof(reason); return 0;
        }
        if(checked(staged,error)) return 1;
    } else return 1;
    memcpy(output,&status,sizeof(status)); *length=sizeof(status); return 0;
}
