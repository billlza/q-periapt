/* SPDX-License-Identifier: Apache-2.0 OR MIT */
_Static_assert(sizeof(qpc_roster_refresh_proposal_v1)==417,"R canonical proposal");
_Static_assert(sizeof(qpc_roster_refresh_scope_v1)==192,"R scope layout");
_Static_assert(sizeof(qpc_roster_refresh_preparation_v1)==424,"R preparation layout");
_Static_assert(sizeof(qpc_roster_refresh_progress_v1)==624,"R progress layout");
_Static_assert(offsetof(qpc_roster_refresh_progress_v1,proposal)==200,"R proposal offset");
_Static_assert(sizeof(qpc_roster_refresh_target_v1)==40,"R target descriptor");
static void roster_progress_print(const qpc_roster_refresh_progress_v1 *p) {
    if(p->phase>5 || p->retired>1 || ((p->phase<3 || p->phase==5) && p->retired)) fail("R progress flags");
    if(p->scope.reserved || p->scope.has_policy_authorization>1) fail("R scope flags");
    for(size_t i=0;i<sizeof(p->reserved);i++) if(p->reserved[i]) fail("R progress padding");
    if(p->phase==0) {const uint8_t *bytes=(const uint8_t *)p;for(size_t i=0;i<sizeof(*p);i++) if(bytes[i]) fail("absent R leaked bytes");}
    if(p->phase==0 || p->phase==1 || p->phase==5) for(size_t i=0;i<sizeof(p->proposal.bytes);i++) if(p->proposal.bytes[i]) fail("unprepared R invented a proposal");
    printf("%u\n%u\n",p->phase,p->retired);encode(p->scope.operation);
    printf("%llu\n",(unsigned long long)p->scope.previous.version);encode(p->scope.previous.digest);
    printf("%llu\n",(unsigned long long)p->scope.target.version);encode(p->scope.target.digest);
    printf("%llu\n",(unsigned long long)p->scope.policy.version);encode(p->scope.policy.digest);
    printf("%u\n",p->scope.has_policy_authorization);encode(p->scope.policy_authorization);
}
static uint32_t roster_select(uint64_t handle,const char *path) {
    uint8_t selected[1];enrollment_exact(path,"roster-policy-source",selected,1);
    if(selected[0]>1) fail("R policy selection");
    if(selected[0]) witness_policy_select(handle,path);
    return selected[0];
}
static int witnessed_roster_command(uint64_t handle,const char *path,const char *mode) {
    qpc_error_v1 error;qpc_roster_refresh_progress_v1 progress;memset(&progress,0xa5,sizeof(progress));
    uint8_t operation[32];enrollment_exact(path,"roster-operation",operation,32);
    if(!strcmp(mode,"progress")) {
        require(qpc_enrollment_v1_witnessed_roster_refresh_progress(handle,&progress,&error),&error);
        if(progress.phase>=2 && progress.phase<=4) {uint8_t saved[417];enrollment_exact(path,"roster-proposal",saved,417);if(memcmp(saved,progress.proposal.bytes,417)) fail("R progress proposal changed");}
        roster_progress_print(&progress);close_owner(handle);return 0;
    }
    if(!strcmp(mode,"prepare") || !strcmp(mode,"prepare-lost") || !strcmp(mode,"prepare-wrong-policy")) {
        uint32_t source=roster_select(handle,path);
        uint8_t certificate[8192],roster[8192],root[1985],version[8];
        qpc_account_pin_v1 pin=enrollment_pin(path,root,0);enrollment_exact(path,"roster-target-version",version,8);pin.checkpoint.version=enrollment_counter(version);enrollment_exact(path,"roster-target-digest",pin.checkpoint.digest,32);
        qpc_roster_refresh_target_v1 target={.certificate=certificate,.certificate_length=enrollment_read(path,"grant-certificate",certificate,8192),.roster=roster,.roster_length=enrollment_read(path,"roster-target",roster,8192),.pin=&pin};
        qpc_roster_refresh_proposal_v1 proposal;memset(&proposal,0xa5,sizeof(proposal));
        int32_t expected=!strcmp(mode,"prepare-lost") ? QPC_ANCHOR : !strcmp(mode,"prepare-wrong-policy") ? QPC_SCOPE : QPC_OK;
        if(!strcmp(mode,"prepare-wrong-policy")) source=QPC_ROSTER_POLICY_ORIGINAL;
        int32_t code=qpc_enrollment_v1_prepare_witnessed_roster_refresh(handle,operation,source,&target,&proposal,&error);record(code,&error);
        if(code!=expected) {require(code,&error);fail("R prepare result differs");}
        if(code) {for(size_t i=0;i<sizeof(proposal.bytes);i++) if(proposal.bytes[i]!=0xa5) fail("failed R prep published bytes");qpc_enrollment_status_v1 owner;code=qpc_enrollment_v1_status(handle,&owner,&error);record(code,&error);if(code!=QPC_CLOSED) fail("failed R prep retained owner");close_owner(handle);printf("roster-refused:%d\n",expected);return 0;}
        qpc_roster_refresh_proposal_v1 repeated;require(qpc_enrollment_v1_prepare_witnessed_roster_refresh(handle,operation,source,&target,&repeated,&error),&error);
        if(memcmp(&proposal,&repeated,sizeof(proposal))) fail("R target resealed");
        enrollment_write(path,"roster-proposal",proposal.bytes,417);close_owner(handle);puts("roster-prepared");return 0;
    }
    if(!strcmp(mode,"recover") || !strcmp(mode,"recover-absent")) {
        qpc_roster_refresh_preparation_v1 result;memset(&result,0xa5,sizeof(result));
        require(qpc_enrollment_v1_recover_witnessed_roster_refresh_preparation(handle,&result,&error),&error);
        for(size_t i=0;i<sizeof(result.reserved);i++) if(result.reserved[i]) fail("R preparation padding");
        int absent=!strcmp(mode,"recover-absent");if(result.present!=(absent ? 0U : 1U)) fail("R local absence differs");
        if(absent) {for(size_t i=0;i<417;i++) if(result.proposal.bytes[i]) fail("absent preparation bytes");}
        else {uint8_t expected[417];enrollment_exact(path,"roster-proposal",expected,417);if(memcmp(expected,result.proposal.bytes,417)) fail("R recovered another target");}
        close_owner(handle);puts(absent ? "roster-local-absence" : "roster-exact-preparation");return 0;
    }
    if(!strcmp(mode,"abandon") || !strcmp(mode,"abandon-refused")) {
        int32_t code=qpc_enrollment_v1_abandon_unprepared_roster_refresh(handle,operation,&progress,&error);record(code,&error);
        if(!strcmp(mode,"abandon-refused")) {if(code!=QPC_SCOPE_CONFLICT) fail("reserved R abandoned locally");const uint8_t *bytes=(const uint8_t *)&progress;for(size_t i=0;i<sizeof(progress);i++) if(bytes[i]!=0xa5) fail("failed abandon wrote output");close_owner(handle);puts("roster-abandon-refused");return 0;}
        require(code,&error);if(progress.phase!=5) fail("abandonment invented witness terminal");roster_progress_print(&progress);close_owner(handle);return 0;
    }
    qpc_roster_refresh_proposal_v1 proposal;enrollment_exact(path,"roster-proposal",proposal.bytes,417);
    uint32_t observed=0xa5a5a5a5U;int32_t expected=QPC_OK;
    if(!strcmp(mode,"substitute")) {proposal.bytes[416]^=1;expected=QPC_SCOPE_CONFLICT;}
    else if(!strcmp(mode,"wrong-kind")) {memcpy(proposal.bytes,"QPPWNP01",8);expected=QPC_ENCODING;}
    else if(!strcmp(mode,"cancelled")) {require(qpc_owner_v1_cancel(handle,&error),&error);expected=QPC_CANCELLED;}
    else if(!strcmp(mode,"commit-lost") || !strcmp(mode,"close-lost")) expected=QPC_ANCHOR;
    int32_t code;
    if(!strcmp(mode,"commit") || !strcmp(mode,"commit-lost")) code=qpc_enrollment_v1_commit_witnessed_roster_refresh(handle,&proposal,roster_select(handle,path),&observed,&error);
    else if(!strcmp(mode,"close") || !strcmp(mode,"close-lost")) code=qpc_enrollment_v1_close_witnessed_roster_refresh(handle,&proposal,&observed,&error);
    else if(!strcmp(mode,"reconcile") || expected!=QPC_OK) code=qpc_enrollment_v1_reconcile_witnessed_roster_refresh(handle,&proposal,&observed,&error);
    else fail("unknown R command");
    record(code,&error);if(code!=expected) {require(code,&error);fail("R result differs");}
    if(code) {
        if(observed!=0xa5a5a5a5U) fail("failed R command published result");
        qpc_enrollment_status_v1 owner;int32_t retained=qpc_enrollment_v1_status(handle,&owner,&error);record(retained,&error);
        int32_t want=expected==QPC_ENCODING ? QPC_OK : expected==QPC_CANCELLED ? QPC_CANCELLED : QPC_CLOSED;if(retained!=want) fail("R failure owner semantics differ");
        close_owner(handle);printf("roster-refused:%d\n",expected);return 0;
    }
    if(observed<1 || observed>5) fail("unknown R state");close_owner(handle);printf("roster-state:%u\n",observed);return 0;
}
