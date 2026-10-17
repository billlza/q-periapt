# Windows private storage API observations

This isolated reproduction branch contains no SDK implementation. It informs
the Windows host-store design for product source
`e709b7db1281e63fcdc9fe2e2c09a261c5619244`; its workflow is not a substitute for
the product CI on that source. It is intentionally a separate history so that
native API exploration does not modify the active release candidate.

The executable exclusively creates one disposable directory and public test
files. It observes directory open/flush results under four access masks, then
checks that a non-delete-sharing parent handle blocks renaming the parent,
that relative file rename refuses an existing destination without changing
either file, and that publishing to an absent name retains the original open
file identity and bytes. Regular-file flush is a positive control. Files are
retained until the disposable runner ends; there is no name-based cleanup.

Directory flush failures are recorded observations, never converted into a
successful storage guarantee. Failed controls fail the job. The harness makes
no claim about owner/DACL validation, reparse admission, persistent locks,
database commits, concurrency, crash recovery, or physical power-loss durability.
All of those still need implementation-specific qualification.

References:

- [CreateFileW access and sharing modes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [FlushFileBuffers requirements](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [FILE_RENAME_INFO relative directory and no-replace behavior](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
- [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
