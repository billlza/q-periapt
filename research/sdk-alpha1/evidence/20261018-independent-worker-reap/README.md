# Independent worker teardown repair

Linux job [117680780391](https://github.com/billlza/q-periapt/actions/runs/39129232912/job/117680780391)
completed with failure at the first storage cut. Original volatile interoperability
passed, but the next journal open raised `BlockingIOError` after SIGKILL.
The complete original artifact and terminal log remain in `CAPTURE.zip`.

The harness had launched `sh artifact/python-run.sh ...`; that wrapper owns a
separate Python child. Reaping the shell after killing its process group did not
establish that the child holding the directory lease had finished exiting.
A local identity control records the different shell/owner PIDs. Its direct-child
counterpart records identical PIDs and waits for the actual killed owner.

`worker_process.command()` now uses the already admitted interpreter, isolated
bootstrap, flags and private empty cache prefix of the parent. The parent keeps
that cache prefix until its children finish. Every cut includes the worker's own
PID, and both harnesses require it to equal `Popen.pid` before SIGKILL and wait.
No nonblocking lock, storage check, deadline or assertion was relaxed; no sleep,
lock retry or error-to-success fallback was added. The shared shell launcher and
all storage/protocol implementations are unchanged.

Final local runs retain 16 storage kills/37 checks, six session kills/27 operations,
nine actual native commands and six codec refusals. All 22 cut PID identities,
public command/result hashes and 24 peer source hashes were checked. The capture
contains the successful `storage-02`/`session-02` transcripts and the original
failed hosted artifact. Private state stays outside both captures. The original
failed job remains failed; a new Linux run is required to qualify the correction.
