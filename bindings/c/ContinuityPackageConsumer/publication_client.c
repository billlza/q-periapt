/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Qualification client: the complete fixed four-role plan is host-retained. */
_Static_assert(sizeof(qpc_publication_key_v1)==56,"publication key ABI");
_Static_assert(sizeof(qpc_publication_plan_v1)==72,"publication plan ABI");
_Static_assert(sizeof(qpc_publication_status_v1)==104,"publication status ABI");
static void publication_status_print(const qpc_publication_status_v1 *s) {
    const uint8_t zero[32]={0};
    if(s->state>3 || s->reserved_zero ||
       ((s->state==0 || s->state==3) && memcmp(s->intent,zero,32)) ||
       (s->state!=2 && (memcmp(s->manifest,zero,32) || memcmp(s->artifact,zero,32))) ||
       ((s->state==1 || s->state==2) && !memcmp(s->intent,zero,32)) ||
       (s->state==2 && (!memcmp(s->manifest,zero,32) || !memcmp(s->artifact,zero,32)))) fail("publication state shape");
    printf("publication-state:%u\n",s->state);encode(s->intent);encode(s->manifest);encode(s->artifact);
}
static int publication_command(int argc,char **argv,uint64_t parent) {
    if(argc<3 || argc>4) fail("publication arguments");
    qpc_error_v1 error;uint8_t id[32];qpc_publication_status_v1 status;
    if(!strcmp(argv[1],"publication-next")) {
        if(argc!=3) fail("next publication arguments");
        require(qpc_device_v1_next_publication(parent,id,&error),&error);encode(id);
    } else {
        if(argc!=4) fail("original publication ID missing");decode(argv[3],id);
        if(!strcmp(argv[1],"publication-status")) {
            require(qpc_device_v1_publication_status(parent,id,&status,&error),&error);publication_status_print(&status);
        } else if(!strcmp(argv[1],"publication-retire")) {
            uint8_t *saved=malloc(2U*1024U*1024U);if(!saved) fail("publication allocation");
            size_t n=enrollment_read(argv[2],"publication-artifact",saved,2U*1024U*1024U);
            if(n<104 || memcmp(saved,"QPPUBA01",8) || memcmp(saved+8,id,32)) fail("host-recorded publication identity");
            require(qpc_device_v1_retire_publication(parent,id,saved+72,&status,&error),&error);free(saved);publication_status_print(&status);
        } else if(!strcmp(argv[1],"publication-prepare") || !strcmp(argv[1],"publication-retry") || !strcmp(argv[1],"publication-cancel")) {
            uint8_t bytes[48];enrollment_exact(argv[2],"publication-plan",bytes,sizeof(bytes));
            qpc_publication_key_v1 keys[4]={0};
            qpc_publication_plan_v1 plan={.struct_size=sizeof(plan),.valid_from=enrollment_counter(bytes+32),
                .valid_until=enrollment_counter(bytes+40),.keys=keys,.count=4};
            memcpy(plan.directory,bytes,32);
            for(size_t i=0;i<4;i++) { keys[i].kind=(uint32_t)i+1;keys[i].valid_from=plan.valid_from;keys[i].valid_until=plan.valid_until; }
            size_t capacity=0,length=99;require(qpc_device_v1_publication_size_bound(&plan,&capacity,&error),&error);
            if(capacity<4000 || capacity>2U*1024U*1024U) fail("publication output bound");
            uint8_t *output=malloc(capacity);if(!output) fail("publication allocation");memset(output,17,capacity);
            qpc_publication_status_v1 before,after;
            require(qpc_device_v1_publication_status(parent,id,&before,&error),&error);
            int32_t code=qpc_device_v1_prepare_publication(parent,id,&plan,output,capacity-1,&length,&error);record(code,&error);
            if(code!=QPC_ARGUMENT || length) fail("short publication buffer admitted");
            for(size_t i=0;i<capacity;i++) if(output[i]!=17) fail("partial short-buffer publication output");
            require(qpc_device_v1_publication_status(parent,id,&after,&error),&error);
            if(memcmp(&before,&after,sizeof(before))) fail("short buffer changed original publication state");
            int cancelled=!strcmp(argv[1],"publication-cancel");
            if(cancelled) require(qpc_owner_v1_cancel(parent,&error),&error);
            code=qpc_device_v1_prepare_publication(parent,id,&plan,output,capacity,&length,&error);record(code,&error);
            if(cancelled) {
                if(code!=QPC_CANCELLED || length) fail("publication cancellation released output");
                for(size_t i=0;i<capacity;i++) if(output[i]!=17) fail("partial cancelled publication output");
                puts("publication-cancelled");
            } else {
                require(code,&error);
                if(length<104 || length>capacity || memcmp(output,"QPPUBA01",8) || memcmp(output+8,id,32)) fail("publication output identity");
                require(qpc_device_v1_publication_status(parent,id,&status,&error),&error);
                if(status.state!=2 || memcmp(status.intent,output+40,32) || memcmp(status.artifact,output+72,32)) fail("publication status differs");
                enrollment_write(argv[2],!strcmp(argv[1],"publication-retry") ? "publication-retry" : "publication-artifact",output,length);
                publication_status_print(&status);
            }
            free(output);
        } else fail("unknown publication command");
    }
    require(qpc_owner_v1_close(parent,&error),&error);if(fflush(stdout)) fail("publication stdout");return 0;
}
