// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;
import android.os.Bundle;
import java.io.File;
import java.nio.charset.StandardCharsets;

/** Bounded transfer of original roster qualification inputs only. */
final class RosterInputs {
    private RosterInputs() { }
    static void install(File inputs,Bundle arguments,String operation) throws Exception {
        if(operation.startsWith("roster-witness-selected-"))operation="roster-witness-"+operation.substring("roster-witness-selected-".length());
        String carrier=new String(WitnessInputs.decoded(arguments,"witness-carrier",3,6),StandardCharsets.US_ASCII);
        boolean witnessed=operation.startsWith("roster-witness-");
        if(witnessed) {
            if(!carrier.equals("signed")&&!carrier.equals("tls"))throw new IllegalArgumentException("required roster witness carrier");
            WitnessInputs.install(inputs,arguments);WitnessInputs.installAuthority(inputs,arguments,operation);
        } else {
            if(!carrier.equals("local"))throw new IllegalArgumentException("local roster carrier");
            WitnessInputs.install(inputs,arguments,"witness-carrier",5,5,true);
        }
        boolean peer=operation.startsWith(witnessed?"roster-witness-peer-":"roster-peer-");
        if(!witnessed||!peer) {
            WitnessInputs.install(inputs,arguments,"renewal-roster",1,8192,true);
            WitnessInputs.install(inputs,arguments,"renewal-version",8,8,true);
            WitnessInputs.install(inputs,arguments,"renewal-digest",32,32,true);
        }
        if(witnessed&&!peer) {
            WitnessInputs.install(inputs,arguments,"roster-operation",32,32,true);
            if(!operation.startsWith("roster-witness-prepare")&&!operation.equals("roster-witness-progress")
                    &&!operation.equals("roster-witness-recover")&&!operation.equals("roster-witness-abandon-refused")
                    &&!operation.equals("roster-witness-resolve-local")&&!operation.equals("roster-witness-activate-unmanaged"))
                WitnessInputs.install(inputs,arguments,"roster-proposal",417,417,true);
        }
        if(peer) {
            String action=operation.substring(witnessed?"roster-witness-".length():"roster-".length());
            if(action.startsWith("peer-roster-")) {
                String prefix=action.equals("peer-roster-revoke")||action.equals("peer-roster-revoked-reopen")?"remote-roster-revoked":"remote-roster";
                WitnessInputs.install(inputs,arguments,prefix,1,65536,true);
                WitnessInputs.install(inputs,arguments,prefix+"-version",8,8,true);
                WitnessInputs.install(inputs,arguments,prefix+"-digest",32,32,true);
                if(action.equals("peer-roster-reopen"))WitnessInputs.install(inputs,arguments,"remote-roster-next",32,32,true);
                PeerInputs.install(inputs,arguments,"peer-retry");
            } else PeerInputs.install(inputs,arguments,action);
        }
    }
}
