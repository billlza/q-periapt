# Windows anonymous scratch API observation

This isolated probe uses exclusively created disposable files and public fixture
bytes. It does not implement SDK storage, ACL admission or secret copying.

The candidate route opens an independent delete handle, checks its file identity,
sets DELETE plus POSIX_SEMANTICS, closes that handle, then requires the original
file's name and last link to be gone before its first write. The still-open
original must support write, flush and exact readback. Reusing its former name
must create a distinct file, and closing the original must preserve that new file.

Duplicate-handle and ordinary deletion are diagnostic comparisons. Their
intermediate namespace visibility is recorded, not assumed. Those routes never
copy payload bytes. A handle lacking DELETE access must fail with access denied
and retain the original empty, named, single-link file.

The initial `cbc5667` observation found that both diagnostic routes reported zero
links while their names remained visible on both Windows images. The separate
POSIX route passed actual namespace absence and live-handle read/write controls.
The next control also records name-open results; zero links alone cannot establish
that an empty file has become anonymous. Original observations remain retained.

Microsoft documents the close semantics in
[FILE_DISPOSITION_INFORMATION_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex).
No fallback to traditional deletion is accepted for the candidate anonymous route.
All required control failures fail the job. This is not a crash, power-loss,
privacy, reparse/race, redb or product qualification.
