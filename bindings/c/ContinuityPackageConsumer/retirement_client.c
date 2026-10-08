/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Actual C retirement process consumer; uses only public qpc-owner/1 entry points. */
_Static_assert(sizeof(qpc_retired_proposal_v1)==360, "retired proposal ABI");
_Static_assert(offsetof(qpc_retired_report_info_v1,report)==sizeof(size_t)+8, "retired report ABI");
_Static_assert(sizeof(qpc_retired_report_info_v1)==sizeof(size_t)+40, "retired report padding");
static uint64_t retirement_open(const char *path) {
    uint8_t root[1985], witness_key[1985], proof[3754], counter[8], validity[16];
    uint8_t *replacement=malloc(57794);if(!replacement) fail("replacement allocation");
    enrollment_exact(path,"local-root",root,sizeof(root));
    enrollment_exact(path,"local-generation",counter,sizeof(counter));
    enrollment_exact(path,"enrollment-validity",validity,sizeof(validity));
    qpc_enrollment_intent_v1 intent={.root=root,.root_length=sizeof(root),
        .generation=enrollment_counter(counter),.valid_from=enrollment_counter(validity),
        .valid_until=enrollment_counter(validity+8)};
    enrollment_exact(path,"local-device",intent.device,16);
    enrollment_exact(path,"family",intent.family,32);
    enrollment_exact(path,"witness-public",witness_key,sizeof(witness_key));
    enrollment_exact(path,"retirement-receipt",proof,sizeof(proof));
    qpc_retired_authority_v1 authority={.public_key=witness_key,.public_key_length=sizeof(witness_key),
        .replacement=replacement,.replacement_length=enrollment_read(path,"retirement-proposal",replacement,57794),
        .receipt=proof,.receipt_length=sizeof(proof)};
    enrollment_exact(path,"witness-id",authority.witness,32);
    enrollment_exact(path,"witness-subject",authority.subject,96);
    uint64_t handle=0;qpc_error_v1 error;
    require(qpc_retired_v1_prepare_open((const uint8_t *)path,strlen(path),&intent,&authority,&handle,&error),&error);
    if(!handle) fail("retired pending handle");
    /* Finish must use the admitted snapshots after caller storage is gone. */
    memset(root,0,sizeof(root));memset(witness_key,0,sizeof(witness_key));memset(proof,0,sizeof(proof));
    memset(replacement,0,57794);free(replacement);memset(&intent,0,sizeof(intent));memset(&authority,0,sizeof(authority));
    require(qpc_owner_v1_finish_open(handle,&error),&error);
    return handle;
}
static void retirement_receipts(const char *path,uint8_t inventory[3690],uint8_t report[3730]) {
    enrollment_exact(path,"retirement-inventory-receipt",inventory,3690);
    enrollment_exact(path,"retirement-report-receipt",report,3730);
}
static void retirement_expect_proposal(const char *path,const qpc_retired_proposal_v1 *proposal) {
    uint8_t expected[353];enrollment_exact(path,"retirement-report-proposal",expected,sizeof(expected));
    const uint8_t zero[3]={0};
    if(proposal->present!=1 || memcmp(proposal->bytes,expected,sizeof(expected)) ||
       memcmp(proposal->reserved_zero,zero,3)) fail("retired proposal identity");
}
static uint8_t *retirement_record(const char *path,size_t *length) {
    uint8_t *bytes=malloc(8388608);if(!bytes) fail("retired metadata allocation");
    *length=enrollment_read(path,"retirement-host-report",bytes,8388608);return bytes;
}
static void retirement_prepare_ack(uint64_t handle,const char *path) {
    uint8_t inventory[3690],report[3730];retirement_receipts(path,inventory,report);
    size_t length;uint8_t *record=retirement_record(path,&length);qpc_error_v1 error;qpc_retired_proposal_v1 proposal;
    require(qpc_retired_v1_prepare_acknowledgement(handle,inventory,sizeof(inventory),report,sizeof(report),
        record,length,&proposal,&error),&error);free(record);retirement_expect_proposal(path,&proposal);
    require(qpc_retired_v1_acknowledgement_proposal(handle,&proposal,&error),&error);
    retirement_expect_proposal(path,&proposal);
}
static int retirement_command(int argc,char **argv) {
    if(argc!=4) fail("retirement command arguments");
    const char *path=argv[2],*mode=argv[3];
    uint8_t pid[8];uint64_t process=(uint64_t)getpid();
    for(size_t i=0;i<8;i++) pid[7-i]=(uint8_t)(process>>(8*i));
    char marker[128];int n=snprintf(marker,sizeof(marker),"retirement-process-%s",mode);
    if(n<=0 || (size_t)n>=sizeof(marker)) fail("retirement process marker");
    enrollment_write(path,marker,pid,sizeof(pid));
    uint64_t handle=retirement_open(path);qpc_error_v1 error;
    if(!strcmp(mode,"inventory")) {
        qpc_retired_inventory_v1 inventory;
        require(qpc_retired_v1_inventory(handle,&inventory,&error),&error);
        enrollment_write(path,"retirement-inventory",inventory.bytes,sizeof(inventory.bytes));
        qpc_enrollment_status_v1 status;memset(&status,0xA5,sizeof(status));
        uint8_t unchanged[sizeof(status)];memcpy(unchanged,&status,sizeof(status));
        if(qpc_enrollment_v1_status(handle,&status,&error)!=QPC_OWNER_KIND || memcmp(&status,unchanged,sizeof(status)))
            fail("retired owner gained enrollment authority or changed failure output");
        uint8_t invalid[3690]={0};qpc_retired_proposal_v1 proposal;memset(&proposal,0xA5,sizeof(proposal));
        uint8_t original[sizeof(proposal)];memcpy(original,&proposal,sizeof(proposal));
        if(qpc_retired_v1_prepare_report(handle,invalid,sizeof(invalid)-1,&proposal,&error)!=QPC_ARGUMENT ||
            memcmp(&proposal,original,sizeof(proposal))) fail("short receipt admitted");
        require(qpc_retired_v1_inventory(handle,&inventory,&error),&error);
        if(qpc_retired_v1_prepare_report(handle,invalid,sizeof(invalid),&proposal,&error)!=QPC_ENCODING ||
            memcmp(&proposal,original,sizeof(proposal))) fail("unauthenticated report receipt admitted");
        if(qpc_retired_v1_inventory(handle,&inventory,&error)!=QPC_CLOSED) fail("failed admitted retirement retained owner");
        close_owner(handle);handle=retirement_open(path);
        require(qpc_owner_v1_cancel(handle,&error),&error);
        memset(&inventory,0xA5,sizeof(inventory));qpc_retired_inventory_v1 before=inventory;
        if(qpc_retired_v1_inventory(handle,&inventory,&error)!=QPC_CANCELLED || memcmp(&inventory,&before,sizeof(inventory)))
            fail("retirement cancellation released output");
    } else if(!strcmp(mode,"prepare-report")) {
        uint8_t receipt[3690];enrollment_exact(path,"retirement-inventory-receipt",receipt,sizeof(receipt));
        qpc_retired_proposal_v1 proposal;
        require(qpc_retired_v1_prepare_report(handle,receipt,sizeof(receipt),&proposal,&error),&error);
        if(proposal.present!=1) fail("retirement report absent after preparation");
        enrollment_write(path,"retirement-report-proposal",proposal.bytes,sizeof(proposal.bytes));
        require(qpc_retired_v1_report_proposal(handle,&proposal,&error),&error);retirement_expect_proposal(path,&proposal);
    } else if(!strcmp(mode,"report") || !strcmp(mode,"report-reopen")) {
        uint8_t inventory[3690],receipt[3730];retirement_receipts(path,inventory,receipt);
        qpc_retired_report_info_v1 info;
        require(qpc_retired_v1_load_report(handle,inventory,sizeof(inventory),receipt,sizeof(receipt),&info,&error),&error);
        if(info.views!=1 || info.reserved_zero || info.length<=322 || info.length>8388608) fail("complete retirement report shape");
        uint8_t *record=malloc(info.length);if(!record) fail("retired report allocation");
        require(qpc_retired_v1_copy_report(handle,record,info.length,&error),&error);
        uint8_t proposal[353];enrollment_exact(path,"retirement-report-proposal",proposal,sizeof(proposal));
        if(memcmp(info.report,proposal+321,32)) fail("retired report identity");
        if(!strcmp(mode,"report")) {
            enrollment_write(path,"retirement-host-report",record,info.length);
            /* Lost completion after the host recorded the complete original bytes. */
            _Exit(77);
        }
        size_t length;uint8_t *original=retirement_record(path,&length);
        if(length!=info.length || memcmp(original,record,length)) fail("reopened retirement report differs");
        free(record);free(original);enrollment_write(path,"retirement-report-reopened",info.report,32);
    } else if(!strcmp(mode,"prepare-ack")) {
        retirement_prepare_ack(handle,path);
    } else if(!strcmp(mode,"erase-journal")) {
        uint8_t ack[3730];enrollment_exact(path,"retirement-ack",ack,sizeof(ack));
        require(qpc_retired_v1_erase_journal(handle,ack,sizeof(ack),&error),&error);_Exit(77);
    } else if(!strcmp(mode,"erase-signer")) {
        uint32_t state=99;require(qpc_retired_v1_journal_state(handle,&state,&error),&error);
        if(state!=1) fail("journal not erased before signer");
        uint8_t ack[3730];enrollment_exact(path,"retirement-ack",ack,sizeof(ack));
        require(qpc_retired_v1_prepare_signer_erasure(handle,ack,sizeof(ack),&error),&error);
        require(qpc_retired_v1_signer_state(handle,&state,&error),&error);if(state!=0) fail("original signer not retained");
        require(qpc_retired_v1_erase_signer(handle,&error),&error);_Exit(77);
    } else if(!strcmp(mode,"verify")) {
        retirement_prepare_ack(handle,path);
        size_t length;uint8_t *record=retirement_record(path,&length);
        enrollment_write(path,"retirement-host-report-verified",record,length);free(record);
        uint32_t state=99;require(qpc_retired_v1_journal_state(handle,&state,&error),&error);
        if(state!=1) fail("retired journal terminal missing");
        require(qpc_retired_v1_signer_state(handle,&state,&error),&error);if(state!=1) fail("retired signer terminal missing");
        require(qpc_retired_v1_erase_signer(handle,&error),&error);
        if(qpc_retired_v1_signer_state(handle,&state,&error)!=QPC_CLOSED) fail("signer erasure retained owner");
        uint8_t proposal[353];enrollment_exact(path,"retirement-report-proposal",proposal,sizeof(proposal));
        enrollment_write(path,"retirement-verified",proposal+321,32);
    } else fail("unknown retirement command");
    close_owner(handle);printf("retirement-stage-pass:%s\n",mode);return 0;
}
