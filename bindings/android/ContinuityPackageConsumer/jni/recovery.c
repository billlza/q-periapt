/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "recovery_wire.h"

jlong qpj_prepare_recovery(JNIEnv *env,jclass type,jobjectArray inputs,jint carrier,jint timeout) {
    (void)type;
    if (!qpj_enter(env,"prepare-recovery")) return 0;
    owned_bytes values[2]={{0}};uint64_t handle=0;
    if (carrier<0 || carrier>2 || (carrier==0 ? timeout!=0 : timeout<1 || timeout>10000)) {
        qpj_throw_class(env,"java/lang/IllegalArgumentException","recovery carrier/timeout");goto cleanup;
    }
    const jsize minimum[2]={1,carrier==0 ? 0 : 1}, maximum[2]={4096,carrier==0 ? 0 : 128};
    if (!qpj_copy_fields(env,inputs,values,minimum,maximum,2)) goto cleanup;
    qpc_witness_v1 witness={.address=values[1].data,.address_length=values[1].length,.timeout_ms=(uint32_t)timeout};
    qpc_open_options_v1 options={.kind=2,.quality=0,.carrier=(uint32_t)carrier,.witness=carrier==0 ? NULL : &witness};
    qpc_error_v1 error={0};
    int32_t code=qpc_owner_v1_prepare_open(values[0].data,values[0].length,&options,&handle,&error);
    if(code!=0) qpj_throw_error(env,"prepare-recovery",code,&error);
cleanup:
    for(size_t i=0;i<2;i++) qpj_dispose(&values[i]);
    qpj_leave();return (jlong)handle;
}

static int shape(jint operation,jsize *input,jsize *output) {
    *input=0;
    switch(operation) {
    case 1:case 11:case 22:case 32:*input=32;*output=0;return 1;
    case 2:*output=72;return 1;
    case 3:case 26:*output=36;return 1;
    case 4:*output=2856;return 1;
    case 5:*output=136;return 1;
    case 6:case 9:case 27:case 30:*output=48;return 1;
    case 7:case 28:*output=104;return 1;
    case 8:case 29:*output=64;return 1;
    case 10:case 31:*output=8;return 1;
    case 12:case 34:*output=0;return 1;
    case 20:*output=4;return 1;
    case 21:*output=32;return 1;
    case 23:*input=QPC_CLOSURE_ARCHIVE_BYTES;*output=0;return 1;
    case 24:*output=QPC_CLOSURE_ARCHIVE_BYTES;return 1;
    case 25:*output=200;return 1;
    case 33:*input=32;*output=1;return 1;
    default:return 0;
    }
}
jbyteArray qpj_recovery_command(JNIEnv *env,jclass type,jlong handle,jint operation,jobjectArray inputs,
        jint member,jint epoch,jint index) {
    (void)type;
    if(!qpj_enter(env,"recovery")) return NULL;
    owned_bytes value[1]={{0}};jbyteArray result=NULL;jsize input=0,output=0;
    int uses_member=operation>=5 && operation<=10;
    int uses_epoch=(operation>=7 && operation<=10) || (operation>=28 && operation<=31);
    int uses_index=(operation>=8 && operation<=10) || operation==21 || operation==27 || (operation>=29 && operation<=31);
    if(!shape(operation,&input,&output) || member<0 || epoch<0 || index<0
            || (!uses_member && member!=0) || (!uses_epoch && epoch!=0) || (!uses_index && index!=0)) {
        qpj_throw_class(env,"java/lang/IllegalArgumentException","recovery operation/index");goto cleanup;
    }
    if(!qpj_copy_fields(env,inputs,value,&input,&input,input==0 ? 0 : 1)) goto cleanup;
    result=(*env)->NewByteArray(env,output);if(result==NULL) goto cleanup;
    uint8_t wire[2856]={0};qpc_error_v1 error={0};
    int32_t code=operation<20
        ? qpj_recovery_account((uint64_t)handle,operation,value[0].data,(uint32_t)member,(uint32_t)epoch,(uint32_t)index,wire,&error)
        : qpj_recovery_session((uint64_t)handle,operation,value[0].data,(uint32_t)epoch,(uint32_t)index,wire,&error);
    if(code!=0) {qpj_throw_error(env,"recovery",code,&error);goto cleanup;}
    if(output!=0) (*env)->SetByteArrayRegion(env,result,0,output,(const jbyte *)wire);
cleanup:
    qpj_dispose(&value[0]);qpj_leave();
    if((*env)->ExceptionCheck(env)) {if(result!=NULL) (*env)->DeleteLocalRef(env,result);return NULL;}
    return result;
}
