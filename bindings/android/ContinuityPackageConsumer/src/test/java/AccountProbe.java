// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Fresh process facade over an original two-recipient account transaction. */
public final class AccountProbe {
    private AccountProbe() { }
    private static final byte[] PAYLOAD = "persisted before process exit".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AD = "configuration-v1".getBytes(StandardCharsets.UTF_8);
    private static byte[] status(AccountStatus value) {
        return ByteBuffer.allocate(33).put((byte)value.phase().ordinal())
            .put(value.report() == null ? new byte[32] : value.report().encoded()).array();
    }
    private static byte[] delivery(AccountDelivery value) {
        return ByteBuffer.allocate(88).put(value.device()).put(value.session().encoded()).put(value.message().encoded())
            .putInt(value.outcome().ordinal()+1).putInt(value.exchanges()).array();
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        String profile=args[2], mode=args[3]; boolean recovery=profile.equals("recoverable");
        require(recovery || profile.equals("fixed"),"profile");
        try (ContinuityDevice device = PeerProbe.device(inputs,installation,recovery)) {
            if (mode.equals("account-next")) publish(output,device.nextAccountOperation().encoded());
            else if (mode.equals("account-status")) publish(output,status(device.accountStatus(new Ids.AccountOperation(read(inputs,"account-operation")))));
            else peers(device,inputs,mode,output);
        }
        System.out.println(profile+":"+mode+":passed");
    }
    private static void peers(ContinuityDevice device, Path inputs, String mode, Path output) throws Exception {
        boolean connect=mode.equals("account-connect");
        byte[] wire=connect ? null : read(inputs,"account-sessions");
        if (!connect) require(wire.length==64,"session pair width");
        Ids.Session first=connect ? null : new Ids.Session(Arrays.copyOfRange(wire,0,32));
        Ids.Session second=connect ? null : new Ids.Session(Arrays.copyOfRange(wire,32,64));
        PeerConfiguration a=PeerProbe.configuration(inputs.resolve("account-peer-0"));
        PeerConfiguration b=PeerProbe.configuration(inputs.resolve("account-peer-1"));
        try (ContinuityPeer peer0=connect ? device.preparePeer(a,PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR)
                : device.preparePeerReopen(a,PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,first);
             ContinuityPeer peer1=connect ? device.preparePeer(b,PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR)
                : device.preparePeerReopen(b,PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,second)) {
            peer0.finishOpen();peer1.finishOpen();
            if (connect) {
                Ids.Session s0=peer0.establish(new String(read(inputs,"account-address-0"),StandardCharsets.US_ASCII),
                    new Ids.Initiation(read(inputs,"account-initiation-0"))).session();
                Ids.Session s1=peer1.establish(new String(read(inputs,"account-address-1"),StandardCharsets.US_ASCII),
                    new Ids.Initiation(read(inputs,"account-initiation-1"))).session();
                publish(output,ByteBuffer.allocate(64).put(s0.encoded()).put(s1.encoded()).array());return;
            }
            AccountTarget[] targets={new AccountTarget(peer0,first),new AccountTarget(peer1,second)};
            int selected=ByteBuffer.wrap(read(inputs,"account-selected")).getInt();
            String address=new String(read(inputs,"account-address"),StandardCharsets.US_ASCII);
            Ids.AccountOperation operation=new Ids.AccountOperation(read(inputs,"account-operation"));
            Ids.Account account=new Ids.Account(read(inputs,"account-recipient"));
            if (mode.equals("account-concurrent")) {
                AccountConcurrentProbe.run(device,operation,account,targets,PAYLOAD,AD);
                publish(output,ByteBuffer.allocate(4).putInt(302).array());return;
            }
            byte[] payload=PAYLOAD.clone();int refused=0;
            switch (mode) {
                case "account-omit" -> { targets=Arrays.copyOf(targets,1);selected=0;refused=106; }
                case "account-omit-retained" -> { targets=Arrays.copyOf(targets,1);selected=0;refused=211; }
                case "account-duplicate-peer" -> { targets[1]=new AccountTarget(peer0,second);refused=1; }
                case "account-duplicate-session" -> { targets[1]=new AccountTarget(peer1,first);refused=1; }
                case "account-cancelled-peer" -> { peer1.cancel();refused=302; }
                case "account-changed" -> { payload[0]^=1;refused=211; }
                case "account-unknown" -> refused=311;
                case "account-reversed" -> { targets=new AccountTarget[] {targets[1],targets[0]};selected=1-selected; }
                case "account-send" -> { }
                default -> throw new IllegalArgumentException("account mode");
            }
            byte[] originalPayload=payload.clone(),originalAd=AD.clone();
            try {
                AccountDelivery result=device.sendAccountMember(operation,account,targets,selected,address,payload,originalAd);
                require(refused==0,"expected native refusal "+refused);
                publish(output,delivery(result));
            } catch (ContinuityFailure failure) {
                require(refused!=0 && failure.code()==refused,"unexpected account failure "+failure.code());
                publish(output,ByteBuffer.allocate(4).putInt(failure.code()).array());
            } finally {
                require(Arrays.equals(payload,originalPayload) && Arrays.equals(originalAd,AD),"caller input mutated");
            }
        }
    }
}
