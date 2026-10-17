#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

struct report { const char *name; unsigned failures; };

static void observe(struct report *r, const char *operation, BOOL ok, DWORD error) {
    if (printf("{\"case\":\"%s\",\"operation\":\"%s\",\"succeeded\":%s,\"win32_error\":%lu}\n",
               r->name, operation, ok ? "true" : "false", error) < 0) r->failures++;
}
static BOOL require(struct report *r, const char *operation, BOOL ok) {
    observe(r, operation, ok, ok ? ERROR_SUCCESS : ERROR_INVALID_DATA);
    if (!ok) r->failures++;
    return ok;
}
static BOOL call(struct report *r, const char *operation, BOOL ok) {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    observe(r, operation, ok, error);
    if (!ok) r->failures++;
    return ok;
}
static BOOL close_owned(struct report *r, HANDLE *file) {
    if (*file != INVALID_HANDLE_VALUE) {
        BOOL ok = call(r, "close_owned_handle", CloseHandle(*file));
        *file = INVALID_HANDLE_VALUE;
        return ok;
    }
    return TRUE;
}
static BOOL path_for(struct report *r, WCHAR *out, size_t count, const WCHAR *root, const WCHAR *leaf) {
    if (!require(r, "bounded_path", wcslen(root) + wcslen(leaf) + 2 < count)) return FALSE;
    return require(r, "path_formed", swprintf_s(out, count, L"%ls\\%ls", root, leaf) > 0);
}
static BOOL visible(struct report *r, const WCHAR *path, BOOL *present) {
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(path, &data);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        observe(r, "namespace_lookup", FALSE, error);
        *present = FALSE;
        return require(r, "lookup_reports_exact_absence", error == ERROR_FILE_NOT_FOUND);
    }
    *present = TRUE;
    observe(r, "namespace_lookup", TRUE, ERROR_SUCCESS);
    return call(r, "close_namespace_query", FindClose(find));
}
static BOOL info(struct report *r, HANDLE file, BY_HANDLE_FILE_INFORMATION *out) {
    return call(r, "handle_information", GetFileInformationByHandle(file, out));
}
static BOOL same(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b) {
    return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber &&
           a->nFileIndexHigh == b->nFileIndexHigh && a->nFileIndexLow == b->nFileIndexLow;
}
static BOOL empty(const BY_HANDLE_FILE_INFORMATION *a) {
    return a->nFileSizeHigh == 0 && a->nFileSizeLow == 0;
}
static BOOL read_exact(struct report *r, HANDLE file, const char *expected, DWORD count) {
    LARGE_INTEGER zero = {0};
    char bytes[64];
    DWORD actual = 0;
    if (!call(r, "seek_for_readback", SetFilePointerEx(file, zero, NULL, FILE_BEGIN))) return FALSE;
    if (!call(r, "handle_readback", ReadFile(file, bytes, (DWORD)sizeof(bytes), &actual, NULL))) return FALSE;
    return require(r, "exact_readback", actual == count && memcmp(bytes, expected, count) == 0);
}
static BOOL write_exact(struct report *r, HANDLE file, const char *bytes, DWORD count) {
    DWORD written = 0;
    if (!call(r, "handle_write", WriteFile(file, bytes, count, &written, NULL))) return FALSE;
    if (!require(r, "complete_write", written == count)) return FALSE;
    return call(r, "handle_flush", FlushFileBuffers(file));
}

/* Only separate-posix is a candidate anonymous route. The other two cases
   record namespace visibility without prescribing unverified duplicate semantics. */
static void deletion_case(struct report *r, const WCHAR *root, const WCHAR *leaf, BOOL duplicate, BOOL posix) {
    WCHAR path[1024];
    HANDLE primary = INVALID_HANDLE_VALUE, deletion = INVALID_HANDLE_VALUE, replacement = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION original, second, current, replaced;
    BOOL present = FALSE;
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const char payload[] = "public scratch fixture";
    const char other[] = "independent replacement";
    if (!path_for(r, path, 1024, root, leaf)) return;
    primary = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE, share, NULL, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (!call(r, "exclusive_empty_file", primary != INVALID_HANDLE_VALUE)) goto done;
    if (!info(r, primary, &original)) goto done;
    if (!require(r, "initial_single_link_regular_empty", empty(&original) && original.nNumberOfLinks == 1 &&
                 (original.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0)) goto done;
    if (duplicate) {
        HANDLE raw = NULL;
        if (!call(r, "duplicate_original_handle", DuplicateHandle(GetCurrentProcess(), primary, GetCurrentProcess(),
                  &raw, 0, FALSE, DUPLICATE_SAME_ACCESS))) goto done;
        deletion = raw;
    } else {
        deletion = CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES, share, NULL, OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (!call(r, "independently_open_delete_handle", deletion != INVALID_HANDLE_VALUE)) goto done;
    }
    if (!info(r, deletion, &second) || !require(r, "delete_handle_is_original_file", same(&original, &second))) goto done;
    FILE_DISPOSITION_INFO_EX disposition = { FILE_DISPOSITION_FLAG_DELETE |
                                             (posix ? FILE_DISPOSITION_FLAG_POSIX_SEMANTICS : 0) };
    if (printf("{\"case\":\"%s\",\"operation\":\"disposition_request\",\"flags\":%lu}\n", r->name, disposition.Flags) < 0) r->failures++;
    if (!call(r, "set_disposition", SetFileInformationByHandle(deletion, FileDispositionInfoEx,
               &disposition, (DWORD)sizeof(disposition)))) goto done;
    if (!close_owned(r, &deletion)) goto done;
    if (!visible(r, path, &present) || !info(r, primary, &current)) goto done;
    if (printf("{\"case\":\"%s\",\"operation\":\"after_delete_handle_close\",\"visible\":%s,\"links\":%lu,\"empty\":%s}\n",
               r->name, present ? "true" : "false", current.nNumberOfLinks, empty(&current) ? "true" : "false") < 0) r->failures++;
    if (!require(r, "original_identity_and_empty_state_retained", same(&original, &current) && empty(&current))) goto done;
    HANDLE lookup = CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL, share, NULL, OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD lookup_error = lookup == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    observe(r, "name_open_after_delete_handle_close", lookup != INVALID_HANDLE_VALUE, lookup_error);
    close_owned(r, &lookup);
    if (!duplicate && posix) {
        if (!require(r, "anonymous_before_first_write", !present && current.nNumberOfLinks == 0)) goto done;
        if (!require(r, "anonymous_name_open_reports_not_found", lookup_error == ERROR_FILE_NOT_FOUND)) goto done;
        if (!write_exact(r, primary, payload, (DWORD)sizeof(payload) - 1)) goto done;
        if (!read_exact(r, primary, payload, (DWORD)sizeof(payload) - 1)) goto done;
        if (!visible(r, path, &present) || !require(r, "still_anonymous_after_io", !present)) goto done;
        replacement = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, share, NULL, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (!call(r, "old_name_can_create_distinct_file", replacement != INVALID_HANDLE_VALUE)) goto done;
        if (!info(r, replacement, &replaced) || !require(r, "replacement_is_distinct_empty_file", !same(&original, &replaced) && empty(&replaced))) goto done;
        if (!write_exact(r, replacement, other, (DWORD)sizeof(other) - 1)) goto done;
        if (!close_owned(r, &primary)) goto done;
        if (!visible(r, path, &present) || !require(r, "original_close_preserves_replacement_name", present)) goto done;
        if (!read_exact(r, replacement, other, (DWORD)sizeof(other) - 1)) goto done;
    } else {
        /* Diagnostic routes never write payload bytes. Closing all references
           must still complete the explicitly requested deletion. */
        if (!close_owned(r, &primary)) goto done;
        if (!visible(r, path, &present)) goto done;
        require(r, "name_absent_after_all_original_handles_close", !present);
    }
done:
    close_owned(r, &deletion);
    close_owned(r, &primary);
    close_owned(r, &replacement);
}

static void missing_delete_right(struct report *r, const WCHAR *root) {
    WCHAR path[1024];
    HANDLE file = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION state;
    BOOL present = FALSE;
    if (!path_for(r, path, 1024, root, L"no-delete-right.bin")) return;
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!call(r, "exclusive_empty_file", file != INVALID_HANDLE_VALUE)) return;
    FILE_DISPOSITION_INFO_EX disposition = { FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS };
    BOOL result = SetFileInformationByHandle(file, FileDispositionInfoEx, &disposition, (DWORD)sizeof(disposition));
    DWORD error = result ? ERROR_SUCCESS : GetLastError();
    observe(r, "disposition_without_delete_right_attempt", result, error);
    require(r, "missing_delete_right_refused", !result && error == ERROR_ACCESS_DENIED);
    if (info(r, file, &state)) require(r, "refusal_keeps_empty_single_link_file", empty(&state) && state.nNumberOfLinks == 1);
    if (visible(r, path, &present)) require(r, "refusal_keeps_original_name", present);
    close_owned(r, &file);
}

int wmain(int argc, WCHAR **argv) {
    struct report setup = { "setup", 0 };
    if (!require(&setup, "one_fixture_argument", argc == 2)) return 1;
    if (!call(&setup, "fresh_fixture_directory", CreateDirectoryW(argv[1], NULL))) return 1;
    WCHAR volume[1024], filesystem[64];
    if (!call(&setup, "volume_path", GetVolumePathNameW(argv[1], volume, 1024))) return 1;
    if (!require(&setup, "fixed_local_volume", GetDriveTypeW(volume) == DRIVE_FIXED)) return 1;
    if (!call(&setup, "volume_information", GetVolumeInformationW(volume, NULL, 0, NULL, NULL, NULL, filesystem, 64))) return 1;
    if (!require(&setup, "local_test_filesystem_ntfs", wcscmp(filesystem, L"NTFS") == 0)) return 1;
    struct report separate = { "separate-posix", 0 }, duplicated = { "duplicate-posix", 0 };
    struct report traditional = { "separate-traditional", 0 }, denied = { "missing-delete-right", 0 };
    deletion_case(&separate, argv[1], L"separate-posix.bin", FALSE, TRUE);
    deletion_case(&duplicated, argv[1], L"duplicate-posix.bin", TRUE, TRUE);
    deletion_case(&traditional, argv[1], L"separate-traditional.bin", FALSE, FALSE);
    missing_delete_right(&denied, argv[1]);
    unsigned failures = setup.failures + separate.failures + duplicated.failures + traditional.failures + denied.failures;
    if (printf("{\"observations_completed\":%s,\"control_failures\":%u,\"power_loss_tested\":false,\"product_qualification\":false}\n",
               failures == 0 ? "true" : "false", failures) < 0) return 1;
    return failures == 0 ? 0 : 1;
}
