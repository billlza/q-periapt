/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "recovery_wire.h"

int32_t qpj_recovery_account(uint64_t handle, jint operation, const uint8_t *input,
        uint32_t member, uint32_t epoch, uint32_t index, uint8_t *out, qpc_error_v1 *error) {
    int32_t code;
    switch(operation) {
    case 1:return qpc_recovery_v1_select_account(handle,input,error);
    case 2: {
        qpc_account_cleanup_header_v1 v={0};code=qpc_recovery_v1_account_begin(handle,&v,error);
        memcpy(out,v.batch,32);memcpy(out+32,v.report,32);qpj_rw32(out+64,v.member_count);qpj_rw32(out+68,v.reserved_zero);return code;
    }
    case 3: {
        qpc_account_cleanup_status_v1 v={0};code=qpc_recovery_v1_account_status(handle,&v,error);
        qpj_rw32(out,v.phase);memcpy(out+4,v.report,32);return code;
    }
    case 4: {
        qpc_account_reconciliation_v1 v={0};code=qpc_recovery_v1_account_reconciliation(handle,&v,error);
        memcpy(out,v.batch,32);qpj_rw32(out+32,v.member_count);qpj_rw32(out+36,v.reserved_zero);
        for(size_t i=0;i<32;i++) {
            uint8_t *p=out+40+i*88;const qpc_account_reconciled_member_v1 *m=&v.members[i];
            memcpy(p,m->device,16);memcpy(p+16,m->session,32);memcpy(p+48,m->message,32);
            qpj_rw32(p+80,m->state);qpj_rw32(p+84,m->reserved_zero);
        }
        return code;
    }
    case 5: {
        qpc_account_cleanup_member_v1 v={0};code=qpc_recovery_v1_account_member(handle,member,&v,error);
        qpj_rw64(out,v.generation);qpj_rw64(out+8,v.confirmed_epoch);qpj_rw64(out+16,v.sending_epoch);
        qpj_rw64(out+24,v.receiving_epoch);qpj_rw64(out+32,v.pending_epoch);qpj_rw32(out+40,v.has_pending_epoch);
        qpj_rw32(out+44,v.role);qpj_rw32(out+48,v.epoch_count);qpj_rw32(out+52,v.reserved_zero);
        memcpy(out+56,v.device,16);memcpy(out+72,v.context,32);memcpy(out+104,v.session,32);return code;
    }
    case 6: {
        qpc_closure_reserved_v1 v={0};code=qpc_recovery_v1_account_reserved(handle,member,&v,error);
        qpj_rw_reservation(out,&v);return code;
    }
    case 7: {
        qpc_closure_epoch_v1 v={0};code=qpc_recovery_v1_account_epoch(handle,member,epoch,&v,error);
        qpj_rw_epoch(out,&v);return code;
    }
    case 8: {
        qpc_closure_unconfirmed_v1 v={0};code=qpc_recovery_v1_account_unconfirmed(handle,member,epoch,index,&v,error);
        memcpy(out,v.message,32);memcpy(out+32,v.ciphertext_digest,32);return code;
    }
    case 9: {
        qpc_closure_delivery_v1 v={0};code=qpc_recovery_v1_account_delivery(handle,member,epoch,index,&v,error);
        qpj_rw_delivery(out,&v);return code;
    }
    case 10: {
        uint64_t position=0;code=qpc_recovery_v1_account_skipped(handle,member,epoch,index,&position,error);
        qpj_rw64(out,position);return code;
    }
    case 11:return qpc_recovery_v1_account_acknowledge(handle,input,error);
    case 12:return qpc_recovery_v1_account_retire(handle,error);
    default:return QPC_ARGUMENT;
    }
}
