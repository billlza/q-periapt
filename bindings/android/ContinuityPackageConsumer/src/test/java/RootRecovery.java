// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Reopens original, transitioned or adopted authority using independently retained approvals. */
final class RootRecovery {
    private RootRecovery() { }
    private static RootReplacementPlan original(Path inputs) throws Exception {
        return new RootReplacementPlan(read(inputs,"root-plan"));
    }
    private static RootReplacementTransition transition(Path inputs) throws Exception {
        return new RootReplacementTransition(original(inputs),new RootReplacementPlan(read(inputs,"root-next-plan")),
            read(inputs,"root-noncommit"),read(inputs,"root-freeze"));
    }
    private static RootReplacementAdoption adoption(Path inputs) throws Exception {
        return new RootReplacementAdoption(original(inputs),new RootReplacementProposal(read(inputs,"root-winner")),
            read(inputs,"root-noncommit"),read(inputs,"root-retirement"));
    }
    static void resume(ContinuityAccountAuthority root,Path inputs,Path installation,String mode) throws Exception {
        String route=new String(read(inputs,"root-route"),StandardCharsets.US_ASCII);
        boolean before=mode.startsWith("root-noncommit-")||mode.equals("root-cancel-preparing")||mode.equals("root-state")||mode.equals("root-freeze-bad")||mode.equals("root-freeze-original")
            ||mode.equals("root-transition-unknown")||mode.equals("root-adopt-unknown");
        if(before||route.equals("original")) {
            root.resumeRootReplacement(installation.toString(),intent(inputs),RootOwnedProbe.scope(inputs),original(inputs));
        } else if(route.equals("transition")||route.equals("bound-transition")||route.equals("noncommit")) {
            root.resumeRootTransition(installation.toString(),intent(inputs),RootOwnedProbe.scope(inputs),transition(inputs));
        } else if(route.equals("adoption")) {
            root.resumeRootAdoption(installation.toString(),intent(inputs),RootOwnedProbe.scope(inputs),adoption(inputs));
        } else throw new IllegalArgumentException("root recovery route");
    }
    static boolean apply(ContinuityAccountAuthority root,Path inputs,Path output,String mode,RootOwnedProbe.CutObserver observer) throws Exception {
        switch(mode) {
            case "root-freeze-original":RootOwnedProbe.cut(output,root.bindRootFreeze(read(inputs,"root-freeze")).encoded(),observer);return true;
            case "root-transition-unknown":RootOwnedProbe.cut(output,root.transitionRoot(transition(inputs)).encoded(),observer);return true;
            case "root-transition-replay":publish(output,root.transitionRoot(transition(inputs)).encoded());return true;
            case "root-adopt-unknown":RootOwnedProbe.cut(output,RootOwnedProbe.checkpoint(root.adoptRoot(adoption(inputs))),observer);return true;
            case "root-adopt-replay":publish(output,RootOwnedProbe.checkpoint(root.adoptRoot(adoption(inputs))));return true;
            default:return false;
        }
    }
}
