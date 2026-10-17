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

The first run (`2687da9`, Actions run `39059753838`) compiled without warnings
on both runner images. Directory flush required write access, and the parent
handle pin/release control passed. Both relative rename calls returned error
87. That version allocated only `offsetof(FileName) + name_bytes`, omitting
the complete structure's trailing storage and a terminating NUL. The next
revision corrects that probe input before drawing an API-support conclusion;
the original failed controls remain in history and in their uploaded artifacts.

The padded-buffer revision (`ad98a73`, run `39059932782`) still returned error
87 on both images. Padding alone therefore does not explain the failure. The
next comparison retains that failing Win32 relative route unchanged and adds
Win32 absolute-name and native `NtSetInformationFile` relative-name routes,
each with fresh files and the same no-replacement/identity/byte assertions.
The failing route still fails its own CI job. No expected-error substitution
is used to produce an overall passing matrix.

The first comparison build (`40a3375`, run `39060096970`) did not execute:
`/TC` treated the bare `ntdll.lib` argument as a C source. The build command
now passes that import library after `/link`; the compiler failure is retained.

At `2e66c26` (run `39060195227`), both Windows images passed the absolute
Win32 and relative NT routes; the relative Win32 route continued failing with
87. A subsequent refinement additionally opens the published name to compare
its volume/file identity and single-link shape against the original handle,
requires the old name to be absent, and flushes the same pinned parent after
publication. This avoids mistaking identity checks on the original handle
alone, or an earlier flush of an empty directory, for the complete primitive
sequence needed by the store.

The next control retains an open, exclusively locked child file while publishing
its parent directory. It checks collision refusal, plain duplicated-handle close,
nonblocking lock contention before and after publication, independently opened
child identity, directory/parent flush, then byte equality after explicit unlock.
These are Win32 file-lock primitives, not a redb or cross-process SDK test.
The directory sequence is only reached after the file controls succeed; any
failed file or directory control still fails its invocation without a fallback.

References:

- [CreateFileW access and sharing modes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [FlushFileBuffers requirements](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [FILE_RENAME_INFO relative directory and no-replace behavior](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
- [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
- [Native rename structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [NtSetInformationFile, including user-mode entry point](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)
