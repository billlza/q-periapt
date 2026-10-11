/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included by the root qualification client; reuses the public retired API. */
static size_t receipt(root_inputs *in,const char *path,const char *name,size_t expected) {
    size_t length=0;if(load(path,name,in->receipt,sizeof in->receipt,&length) || length!=expected) fail("signed receipt width");
    return length;
}
static void cleanup(uint64_t root,root_inputs *in,const char *path,const char *mode) {
    qpc_error_v1 error;
    if(!strcmp(mode,"inventory")) {
        qpc_retired_inventory_v1 inventory;
        require(qpc_retired_v1_inventory(root,&inventory,&error),&error);
        save(path,"inventory",inventory.bytes,sizeof inventory.bytes);
    } else if(!strcmp(mode,"prepare-report")) {
        size_t n=receipt(in,path,"inventory-receipt",3690);qpc_retired_proposal_v1 proposal;
        require(qpc_retired_v1_prepare_report(root,in->receipt,n,&proposal,&error),&error);
        if(proposal.present!=1) fail("report absent");save(path,"report-proposal",proposal.bytes,sizeof proposal.bytes);
    } else if(!strcmp(mode,"report") || !strcmp(mode,"prepare-ack")) {
        uint8_t inventory[3690];if(fixed(path,"inventory-receipt",inventory,sizeof inventory)) fail("inventory receipt");
        size_t n=receipt(in,path,"report-receipt",3730);qpc_retired_report_info_v1 info;
        require(qpc_retired_v1_load_report(root,inventory,sizeof inventory,in->receipt,n,&info,&error),&error);
        if(!info.length || info.length>8388608 || info.reserved_zero) fail("report size");
        uint8_t *report=malloc(info.length);if(!report) fail("report allocation");
        require(qpc_retired_v1_copy_report(root,report,info.length,&error),&error);
        if(!strcmp(mode,"report")) save(path,"host-report",report,info.length);
        else {
            uint8_t *retained=malloc(info.length);size_t length=0;if(!retained) fail("retained report allocation");
            if(load(path,"host-report",retained,info.length,&length) || length!=info.length || memcmp(retained,report,length)) fail("original report changed");
            qpc_retired_proposal_v1 proposal;
            require(qpc_retired_v1_prepare_acknowledgement(root,inventory,sizeof inventory,in->receipt,n,
                retained,length,&proposal,&error),&error);
            uint8_t expected[353];if(fixed(path,"report-proposal",expected,sizeof expected) || proposal.present!=1 ||
                memcmp(proposal.bytes,expected,sizeof expected)) fail("ACK changed original report identity");
            free(retained);
        }
        free(report);
    } else if(!strcmp(mode,"journal")) {
        size_t n=receipt(in,path,"host-ack",3730);
        require(qpc_retired_v1_erase_journal(root,in->receipt,n,&error),&error);
        uint32_t state=99;require(qpc_retired_v1_journal_state(root,&state,&error),&error);if(state!=1) fail("journal not erased");
    } else if(!strcmp(mode,"signer")) {
        size_t n=receipt(in,path,"host-ack",3730);
        require(qpc_retired_v1_prepare_signer_erasure(root,in->receipt,n,&error),&error);
        require(qpc_retired_v1_erase_signer(root,&error),&error);
    } else if(strcmp(mode,"verify")) fail("unknown cleanup stage");
    if(!strcmp(mode,"signer") || !strcmp(mode,"verify")) {
        uint32_t state=99;require(qpc_retired_v1_signer_state(root,&state,&error),&error);if(state!=1) fail("signer not erased");
        require(qpc_retired_v1_journal_state(root,&state,&error),&error);if(state!=1) fail("journal terminal missing");
    }
}
