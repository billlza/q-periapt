/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Exact approved recovery inputs, explicitly selected on every process restart. */
typedef enum { ROOT_ORIGINAL, ROOT_TRANSITION, ROOT_ADOPTION } root_route;
typedef struct {
    uint8_t approved[131072],noncommit[65536],receipt[65536];
    qpc_root_alternative_v1 options;
} root_alternative;
static root_route select_route(const char **mode) {
    if(!strncmp(*mode,"transition:",11)) { *mode+=11;return ROOT_TRANSITION; }
    if(!strncmp(*mode,"adoption:",9)) { *mode+=9;return ROOT_ADOPTION; }
    if(strchr(*mode,':')) fail("unknown root recovery route");
    return ROOT_ORIGINAL;
}
static root_alternative *alternative_inputs(const root_inputs *in,const char *public) {
    root_alternative *a=calloc(1,sizeof *a);if(!a) fail("alternative inputs allocation");
    a->options.struct_size=sizeof a->options;
    a->options.original=in->plan;a->options.original_length=in->plan_length;
    a->options.approved=a->approved;a->options.noncommit=a->noncommit;a->options.receipt=a->receipt;
    if(load(public,"alternative-approved",a->approved,sizeof a->approved,&a->options.approved_length) ||
       load(public,"original-noncommit",a->noncommit,sizeof a->noncommit,&a->options.noncommit_length) ||
       load(public,"alternative-receipt",a->receipt,sizeof a->receipt,&a->options.receipt_length)) fail("retained alternative approval");
    return a;
}
static void resume_root(uint64_t root,const root_inputs *in,const char *public,const char *old,root_route route) {
    qpc_error_v1 error;
    if(route==ROOT_ORIGINAL) {
        require(qpc_root_v1_resume(root,(const uint8_t *)old,strlen(old),&in->original,&in->scope,
                                  in->plan,in->plan_length,&error),&error);return;
    }
    root_alternative *a=alternative_inputs(in,public);
    int32_t code=route==ROOT_TRANSITION ?
        qpc_root_v1_resume_transition(root,(const uint8_t *)old,strlen(old),&in->original,&in->scope,&a->options,&error) :
        qpc_root_v1_resume_adoption(root,(const uint8_t *)old,strlen(old),&in->original,&in->scope,&a->options,&error);
    require(code,&error);free(a);
}
static void alternative(uint64_t root,root_inputs *in,const char *public,const char *mode) {
    root_alternative *a=alternative_inputs(in,public);qpc_error_v1 error;
    if(!strcmp(mode,"transition") || !strcmp(mode,"transition-retry")) {
        size_t written=0;
        require(qpc_root_v1_transition(root,&a->options,in->proposal,sizeof in->proposal,&written,&error),&error);
        if(!strcmp(mode,"transition")) save(public,"bound-proposal",in->proposal,written);
        else {
            size_t length=0;
            if(load(public,"bound-proposal",in->receipt,sizeof in->receipt,&length) ||
               length!=written || memcmp(in->proposal,in->receipt,written)) fail("transition changed proposal identity");
        }
    } else {
        qpc_authority_checkpoint_v1 next;uint8_t account[32];
        require(qpc_root_v1_adopt(root,&a->options,&next,&error),&error);
        if(fixed(public,"target-account",account,32) || memcmp(account,next.account,32) ||
           memcmp(next.application,in->scope.checkpoint.application,32) ||
           next.revision!=in->scope.checkpoint.revision+1) fail("adopted checkpoint differs");
    }
    free(a);
}
