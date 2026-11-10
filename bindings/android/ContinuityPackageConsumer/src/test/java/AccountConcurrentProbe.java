// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Actual blocked TLS call holds all target owners; cancel never needs its monitor. */
final class AccountConcurrentProbe {
    private AccountConcurrentProbe() { }
    static void run(ContinuityDevice device, Ids.AccountOperation operation, Ids.Account account,
            AccountTarget[] targets, byte[] payload, byte[] ad) throws Exception {
        try (ServerSocket listener = new ServerSocket(0,1,java.net.InetAddress.getByAddress(new byte[] {127,0,0,1}))) {
            listener.setSoTimeout(10000);
            String address="127.0.0.1:"+listener.getLocalPort();
            FutureTask<AccountDelivery> task=new FutureTask<>(() -> device.sendAccountMember(operation,account,targets,0,address,payload,ad));
            Thread worker=new Thread(task,"account-delivery");worker.start();
            Throwable primary=null;
            try {
                try (Socket socket=listener.accept()) {
                    socket.setSoTimeout(10000);
                    require(socket.getInputStream().read()>=0,"native TLS never dispatched");
                    failed(3,device::nextAccountOperation);
                    failed(3,device::close);
                    failed(3,targets[0].peer()::close);
                    failed(3,() -> targets[1].peer().nextMessage(targets[1].session()));
                    targets[1].peer().cancel();
                    try { task.get(10,TimeUnit.SECONDS);throw new AssertionError("cancelled aggregate returned success"); }
                    catch (ExecutionException failure) {
                        require(failure.getCause() instanceof ContinuityFailure,"cancellation exception changed");
                        require(((ContinuityFailure)failure.getCause()).code()==302,"cancel code changed");
                    }
                }
                require(device.accountStatus(operation).phase()==AccountStatus.Phase.COMMITTED,"cancelled aggregate commitment lost");
                targets[0].peer().nextMessage(targets[0].session()); // Other owner was not permanently cancelled.
                failed(302,() -> targets[1].peer().nextMessage(targets[1].session()));
            } catch (Throwable failure) { primary=failure;throw failure; }
            finally {
                try {
                    if (worker.isAlive()) device.cancel();
                    worker.join(30000);require(!worker.isAlive(),"aggregate worker failed to stop");
                } catch (Throwable cleanup) {
                    if (primary!=null) primary.addSuppressed(cleanup);else throw cleanup;
                }
            }
        }
    }
}
