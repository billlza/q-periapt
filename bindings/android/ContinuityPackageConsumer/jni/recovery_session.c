/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "recovery_wire.h"

int32_t qpj_recovery_session(uint64_t handle,jint operation,const uint8_t *input,
        uint32_t epoch,uint32_t index,uint8_t *out,qpc_error_v1 *error) {
    int32_t code;
    switch(operation) {
    case 20: {uint32_t count=0;code=qpc_recovery_v1_session_count(handle,&count,error);qpj_rw32(out,count);return code;}
    case 21:return qpc_recovery_v1_session_at(handle,index,out,error);
    case 22:return qpc_recovery_v1_select(handle,input,error);
    case 23:return qpc_recovery_v1_select_archive(handle,input,QPC_CLOSURE_ARCHIVE_BYTES,error);
    case 24:return qpc_recovery_v1_archive(handle,out,error);
    case 25: {
        qpc_closure_header_v1 v={0};code=qpc_recovery_v1_begin(handle,&v,error);
        qpj_rw64(out,v.peer_generation);qpj_rw64(out+8,v.confirmed_epoch);qpj_rw64(out+16,v.sending_epoch);
        qpj_rw64(out+24,v.receiving_epoch);qpj_rw64(out+32,v.pending_epoch);qpj_rw32(out+40,v.has_pending_epoch);
        qpj_rw32(out+44,v.role);qpj_rw32(out+48,v.reserved_count);qpj_rw32(out+52,v.epoch_count);
        memcpy(out+56,v.session,32);memcpy(out+88,v.context,32);memcpy(out+120,v.report,32);
        memcpy(out+152,v.peer_account,32);memcpy(out+184,v.peer_device,16);return code;
    }
    case 26: {
        qpc_closure_status_v1 v={0};code=qpc_recovery_v1_status(handle,&v,error);
        qpj_rw32(out,v.phase);memcpy(out+4,v.report,32);return code;
    }
    case 27: {
        qpc_closure_reserved_v1 v={0};code=qpc_recovery_v1_reserved(handle,index,&v,error);
        qpj_rw_reservation(out,&v);return code;
    }
    case 28: {
        qpc_closure_epoch_v1 v={0};code=qpc_recovery_v1_epoch(handle,epoch,&v,error);
        qpj_rw_epoch(out,&v);return code;
    }
    case 29: {
        qpc_closure_unconfirmed_v1 v={0};code=qpc_recovery_v1_unconfirmed(handle,epoch,index,&v,error);
        memcpy(out,v.message,32);memcpy(out+32,v.ciphertext_digest,32);return code;
    }
    case 30: {
        qpc_closure_delivery_v1 v={0};code=qpc_recovery_v1_delivery(handle,epoch,index,&v,error);
        qpj_rw_delivery(out,&v);return code;
    }
    case 31: {uint64_t position=0;code=qpc_recovery_v1_skipped(handle,epoch,index,&position,error);qpj_rw64(out,position);return code;}
    case 32:return qpc_recovery_v1_acknowledge(handle,input,error);
    case 33:return qpc_recovery_v1_retire(handle,input,out,error);
    case 34:return qpc_recovery_v1_restore_index(handle,error);
    default:return QPC_ARGUMENT;
    }
}
