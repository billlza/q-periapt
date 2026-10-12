/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "policy_codec.h"
#include <stdlib.h>
#include <string.h>

enum { ROOT_BEGIN=1, ROOT_RESUME, ROOT_STATE, ROOT_BIND_FREEZE, ROOT_RETAIN_RETIREMENT,
    ROOT_RETAIN_NONCOMMIT, ROOT_ACTIVATE, ROOT_TRANSITION, ROOT_ADOPT,
    ROOT_RESUME_TRANSITION, ROOT_RESUME_ADOPTION, ROOT_FIELDS=11, ROOT_PROPOSAL_FRAME=65540 };
_Static_assert(ROOT_FIELDS <= QPJ_INPUT_FIELD_LIMIT, "root fields exceed JNI capacity");
static void scope_shape(jsize *minimum, jsize *maximum) {
    const jsize widths[3] = {72,32,1985};
    memcpy(minimum,widths,sizeof(widths)); memcpy(maximum,widths,sizeof(widths));
}
static void alternative_shape(jsize *minimum, jsize *maximum, int adoption) {
    const jsize low[4] = {8,8,3449,1};
    const jsize high[4] = {131072,adoption ? 65536 : 131072,3449,adoption ? 3449 : 131072};
    memcpy(minimum,low,sizeof(low)); memcpy(maximum,high,sizeof(high));
    if (adoption) minimum[3] = 3449;
}
static int shape(jint operation, jsize minimum[ROOT_FIELDS], jsize maximum[ROOT_FIELDS],
        size_t *count, jsize *length, jsize *numbers) {
    *count=0; *length=0; *numbers=0;
    switch(operation) {
        case ROOT_BEGIN:
            *count=4; scope_shape(minimum,maximum); minimum[3]=8; maximum[3]=131072; return 1;
        case ROOT_RESUME: case ROOT_RESUME_TRANSITION: case ROOT_RESUME_ADOPTION: {
            const jsize low[4]={1,1985,16,32}, high[4]={4096,1985,16,32};
            *count=operation==ROOT_RESUME ? 8 : 11; *numbers=3;
            memcpy(minimum,low,sizeof(low)); memcpy(maximum,high,sizeof(high)); scope_shape(minimum+4,maximum+4);
            if(operation==ROOT_RESUME) { minimum[7]=8; maximum[7]=131072; }
            else alternative_shape(minimum+7,maximum+7,operation==ROOT_RESUME_ADOPTION);
            return 1;
        }
        case ROOT_STATE: *length=4; return 1;
        case ROOT_BIND_FREEZE:
            *count=1; *length=ROOT_PROPOSAL_FRAME; minimum[0]=1; maximum[0]=131072; return 1;
        case ROOT_RETAIN_RETIREMENT: case ROOT_RETAIN_NONCOMMIT:
            *count=1; *length=operation==ROOT_RETAIN_RETIREMENT ? 72 : 4; minimum[0]=maximum[0]=3449; return 1;
        case ROOT_ACTIVATE: return 1;
        case ROOT_TRANSITION: case ROOT_ADOPT:
            *count=4; *length=operation==ROOT_TRANSITION ? ROOT_PROPOSAL_FRAME : 72;
            alternative_shape(minimum,maximum,operation==ROOT_ADOPT); return 1;
        default:return 0;
    }
}
static void decode_scope(qpc_root_scope_v1 *scope, const owned_bytes *values) {
    scope->struct_size=(uint32_t)sizeof(*scope);
    memcpy(scope->checkpoint.application,values[0].data,32);
    scope->checkpoint.revision=qpj_policy_u64(values[0].data+32);
    memcpy(scope->checkpoint.account,values[0].data+40,32);
    memcpy(scope->witness,values[1].data,32);
    scope->public_key=values[2].data; scope->public_key_length=values[2].length;
}
static void decode_alternative(qpc_root_alternative_v1 *out, const owned_bytes *values) {
    out->struct_size=(uint32_t)sizeof(*out);
    out->original=values[0].data; out->original_length=values[0].length;
    out->approved=values[1].data; out->approved_length=values[1].length;
    out->noncommit=values[2].data; out->noncommit_length=values[2].length;
    out->receipt=values[3].data; out->receipt_length=values[3].length;
}
/* Preallocate both Java output and native proposal capacity before any persistent change. */
jbyteArray qpj_root_command(JNIEnv *env, jclass type, jlong handle, jlong other,
        jint operation, jobjectArray inputs, jlongArray numbers) {
    (void)type;
    const char *name="account-root-replacement";
    if(!qpj_enter(env,name)) return NULL;
    owned_bytes values[ROOT_FIELDS]={{0}}, wire={0};
    jsize minimum[ROOT_FIELDS]={0}, maximum[ROOT_FIELDS]={0}, length=0, number_count=0;
    size_t count=0, written=0; jlong counters[3]={0}; jbyteArray output=NULL;
    if(!shape(operation,minimum,maximum,&count,&length,&number_count)
            || (other!=0 && operation!=ROOT_BEGIN && operation!=ROOT_ACTIVATE)) {
        qpj_throw_class(env,"java/lang/IllegalArgumentException","root operation selection"); goto cleanup;
    }
    if(numbers==NULL) { qpj_throw_class(env,"java/lang/NullPointerException","root counters"); goto cleanup; }
    if((*env)->GetArrayLength(env,numbers)!=number_count) {
        qpj_throw_class(env,"java/lang/IllegalArgumentException","root counter width"); goto cleanup;
    }
    if(number_count) (*env)->GetLongArrayRegion(env,numbers,0,number_count,counters);
    if((*env)->ExceptionCheck(env) || !qpj_copy_fields(env,inputs,values,minimum,maximum,count)) goto cleanup;
    output=(*env)->NewByteArray(env,length); if(output==NULL) goto cleanup;
    if(length) {
        wire.data=calloc((size_t)length,1); wire.length=(size_t)length;
        if(wire.data==NULL) { qpj_throw_class(env,"java/lang/OutOfMemoryError","root result capacity"); goto cleanup; }
    }
    qpc_root_scope_v1 scope={0}; qpc_root_alternative_v1 alternative={0};
    qpc_enrollment_intent_v1 intent={0}; qpc_authority_checkpoint_v1 checkpoint={0};
    qpc_error_v1 error={0}; uint32_t state=0; int32_t code=0;
    if(operation==ROOT_BEGIN) decode_scope(&scope,values);
    if(number_count) {
        intent.root=values[1].data; intent.root_length=values[1].length;
        memcpy(intent.device,values[2].data,16); memcpy(intent.family,values[3].data,32);
        intent.generation=(uint64_t)counters[0]; intent.valid_from=(uint64_t)counters[1]; intent.valid_until=(uint64_t)counters[2];
        decode_scope(&scope,values+4);
    }
    if(operation==ROOT_TRANSITION || operation==ROOT_ADOPT) decode_alternative(&alternative,values);
    if(operation==ROOT_RESUME_TRANSITION || operation==ROOT_RESUME_ADOPTION) decode_alternative(&alternative,values+7);
    switch(operation) {
        case ROOT_BEGIN: code=qpc_root_v1_begin((uint64_t)handle,(uint64_t)other,&scope,values[3].data,values[3].length,&error); break;
        case ROOT_RESUME: code=qpc_root_v1_resume((uint64_t)handle,values[0].data,values[0].length,&intent,&scope,values[7].data,values[7].length,&error); break;
        case ROOT_STATE: code=qpc_root_v1_state((uint64_t)handle,&state,&error); break;
        case ROOT_BIND_FREEZE: code=qpc_root_v1_bind_freeze((uint64_t)handle,values[0].data,values[0].length,wire.data+4,65536,&written,&error); break;
        case ROOT_RETAIN_RETIREMENT: code=qpc_root_v1_retain_retirement((uint64_t)handle,values[0].data,values[0].length,&checkpoint,&error); break;
        case ROOT_RETAIN_NONCOMMIT: code=qpc_root_v1_retain_noncommit((uint64_t)handle,values[0].data,values[0].length,&state,&error); break;
        case ROOT_ACTIVATE: code=qpc_root_v1_activate_successor((uint64_t)handle,(uint64_t)other,&error); break;
        case ROOT_TRANSITION: code=qpc_root_v1_transition((uint64_t)handle,&alternative,wire.data+4,65536,&written,&error); break;
        case ROOT_ADOPT: code=qpc_root_v1_adopt((uint64_t)handle,&alternative,&checkpoint,&error); break;
        case ROOT_RESUME_TRANSITION: code=qpc_root_v1_resume_transition((uint64_t)handle,values[0].data,values[0].length,&intent,&scope,&alternative,&error); break;
        case ROOT_RESUME_ADOPTION: code=qpc_root_v1_resume_adoption((uint64_t)handle,values[0].data,values[0].length,&intent,&scope,&alternative,&error); break;
        default:qpj_throw_class(env,"java/lang/IllegalStateException","validated root operation changed"); goto cleanup;
    }
    if(code!=0) { qpj_throw_error(env,name,code,&error); goto cleanup; }
    if(length==ROOT_PROPOSAL_FRAME) {
        if(written<8 || written>65536) { qpj_throw_class(env,"java/lang/IllegalStateException","native root proposal length"); goto cleanup; }
        qpj_policy_put32(wire.data,(uint32_t)written);
        memset(wire.data+4+written,0,65536-written);
    } else if(length==72) {
        memcpy(wire.data,checkpoint.application,32); qpj_policy_put64(wire.data+32,checkpoint.revision);
        memcpy(wire.data+40,checkpoint.account,32);
    } else if(length==4) qpj_policy_put32(wire.data,state);
    if(length) (*env)->SetByteArrayRegion(env,output,0,length,(const jbyte *)wire.data);
cleanup:
    for(size_t i=0;i<ROOT_FIELDS;++i) qpj_dispose(&values[i]);
    qpj_dispose(&wire); qpj_leave();
    if((*env)->ExceptionCheck(env)) { if(output!=NULL) (*env)->DeleteLocalRef(env,output); return NULL; }
    return output;
}
