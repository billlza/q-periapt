/* SPDX-License-Identifier: Apache-2.0 OR MIT */
_Static_assert(sizeof(qpc_independent_policy_proposal_v1)==296,"independent P proposal");
_Static_assert(sizeof(qpc_independent_policy_preparation_v1)==304,"independent P preparation");
_Static_assert(sizeof(qpc_independent_policy_progress_v1)==344,"independent P progress");
_Static_assert(offsetof(qpc_independent_policy_progress_v1,target)==304,"independent P checkpoint offset");
static void witness_policy_select(uint64_t handle,const char *path) {
    char target_path[4096];enrollment_path(target_path,path,"independent-sdk");
    uint8_t root[1985],wire[8192];qpc_error_v1 error;
    qpc_policy_document_v1 target=policy_document(target_path,root,wire);
    require(qpc_enrollment_v1_select_continued_policy(handle,(const uint8_t *)target_path,strlen(target_path),&target,&error),&error);
}
static int witnessed_independent_policy_command(uint64_t handle,const char *path,const char *mode) {
    qpc_error_v1 error;
    if(!strcmp(mode,"request")) {
        uint8_t operation[32];enrollment_exact(path,"independent-operation",operation,32);
        qpc_policy_renewal_request_v1 request;memset(&request,0xa5,sizeof(request));
        require(independent_request_on_worker(handle,operation,&request,&error,1),&error);
        enrollment_write(path,"independent-request",(const uint8_t *)&request,sizeof(request));
        close_owner(handle);puts("request-saved");return 0;
    }
    if(!strcmp(mode,"prepare")) {
        witness_policy_select(handle,path);
        uint8_t root[1985],wire[8192];qpc_policy_document_v1 previous=policy_document(path,root,wire);
        qpc_independent_policy_proposal_v1 proposal,repeated;
        require(qpc_enrollment_v1_prepare_witnessed_policy_renewal(handle,&previous,&proposal,&error),&error);
        require(qpc_enrollment_v1_prepare_witnessed_policy_renewal(handle,&previous,&repeated,&error),&error);
        if(memcmp(&proposal,&repeated,sizeof(proposal))) fail("P retry resealed target");
        enrollment_write(path,"independent-witness-proposal",proposal.bytes,sizeof(proposal.bytes));
        close_owner(handle);puts("proposal-saved");return 0;
    }
    if(!strcmp(mode,"recover") || !strcmp(mode,"recover-absent")) {
        qpc_independent_policy_preparation_v1 result;memset(&result,0xa5,sizeof(result));
        require(qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation(handle,&result,&error),&error);
        if(result.reserved || result.present>1) fail("noncanonical P preparation flags");
        if(!strcmp(mode,"recover-absent")) {
            if(result.present) fail("unexpected local preparation");
            for(size_t i=0;i<sizeof(result.proposal.bytes);i++) if(result.proposal.bytes[i]) fail("absent preparation leaked data");
            close_owner(handle);puts("preparation-absent");return 0;
        }
        qpc_independent_policy_proposal_v1 expected;enrollment_exact(path,"independent-witness-proposal",expected.bytes,sizeof(expected.bytes));
        if(result.present!=1 || memcmp(&result.proposal,&expected,sizeof(expected))) fail("changed original preparation");
        close_owner(handle);puts("preparation-exact");return 0;
    }
    if(!strcmp(mode,"progress")) {
        qpc_independent_policy_progress_v1 result;memset(&result,0xa5,sizeof(result));
        require(qpc_enrollment_v1_witnessed_policy_renewal_progress(handle,&result,&error),&error);
        if(result.phase>3 || result.retired>1 || (result.phase<2 && result.retired)) fail("P progress flags");
        if(result.phase) {
            qpc_independent_policy_proposal_v1 expected;enrollment_exact(path,"independent-witness-proposal",expected.bytes,sizeof(expected.bytes));
            if(memcmp(&result.proposal,&expected,sizeof(expected))) fail("progress changed original proposal");
        } else {
            const uint8_t *bytes=(const uint8_t *)&result;for(size_t i=0;i<sizeof(result);i++) if(bytes[i]) fail("absent progress leaked bytes");
        }
        printf("%u\n%u\n%llu\n",result.phase,result.retired,(unsigned long long)result.target.version);encode(result.target.digest);
        close_owner(handle);return 0;
    }
    qpc_independent_policy_proposal_v1 proposal;enrollment_exact(path,"independent-witness-proposal",proposal.bytes,sizeof(proposal.bytes));
    uint32_t observed=0xa5a5a5a5U;int32_t expected=QPC_OK;
    if(!strcmp(mode,"substitute")) {proposal.bytes[295]^=1;expected=QPC_SCOPE_CONFLICT;}
    else if(!strcmp(mode,"wrong-kind")) {memcpy(proposal.bytes,"QPCRNP01",8);expected=QPC_ENCODING;}
    else if(!strcmp(mode,"cancelled")) {require(qpc_owner_v1_cancel(handle,&error),&error);expected=QPC_CANCELLED;}
    else if(!strcmp(mode,"commit-lost") || !strcmp(mode,"close-lost") || !strcmp(mode,"reconcile-lost")) expected=QPC_ANCHOR;
    int32_t code;
    if(!strcmp(mode,"commit") || !strcmp(mode,"commit-lost")) {
        witness_policy_select(handle,path);
        code=qpc_enrollment_v1_commit_witnessed_policy_renewal(handle,&proposal,&observed,&error);
    } else if(!strcmp(mode,"close") || !strcmp(mode,"close-lost")) {
        code=qpc_enrollment_v1_close_witnessed_policy_renewal(handle,&proposal,&observed,&error);
    } else if(!strcmp(mode,"reconcile") || !strcmp(mode,"reconcile-lost") || expected!=QPC_OK) {
        code=qpc_enrollment_v1_reconcile_witnessed_policy_renewal(handle,&proposal,&observed,&error);
    } else fail("unknown witness P mode");
    record(code,&error);
    if(code!=expected) {require(code,&error);fail("witness P failure differs");}
    if(expected!=QPC_OK) {
        if(observed!=0xa5a5a5a5U) fail("failed witness call published outcome");
        qpc_enrollment_status_v1 status;int32_t check=qpc_enrollment_v1_status(handle,&status,&error);record(check,&error);
        int32_t expected_owner=expected==QPC_ENCODING ? QPC_OK : expected==QPC_CANCELLED ? QPC_CANCELLED : QPC_CLOSED;
        if(check!=expected_owner) fail("witness failure owner state differs");
        close_owner(handle);printf("witness-refused:%d\n",expected);return 0;
    }
    if(observed<1 || observed>5) fail("invalid typed witness state");
    close_owner(handle);printf("witness-state:%u\n",observed);return 0;
}
