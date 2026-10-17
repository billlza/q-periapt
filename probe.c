/* Native Windows API observations, using only disposable public test bytes. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* The SDK supplies IO_STATUS_BLOCK. The documented native entry point is
   imported from ntdll for user mode, with FileRenameInformation = 10. */
NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID,
                                            ULONG, FILE_INFORMATION_CLASS);

enum rename_method { WIN32_RELATIVE, WIN32_ABSOLUTE, NT_RELATIVE };

static int failures = 0;

static void observe(const char *name, BOOL ok, DWORD error) {
    if (printf("{\"operation\":\"%s\",\"succeeded\":%s,\"win32_error\":%lu}\n",
               name, ok ? "true" : "false", ok ? 0UL : error) < 0) {
        failures++;
    }
}

static void require(const char *name, BOOL ok) {
    observe(name, ok, ok ? ERROR_SUCCESS : ERROR_INVALID_DATA);
    if (!ok) failures++;
}

static void close_owned(HANDLE handle) {
    if (handle != INVALID_HANDLE_VALUE) {
        BOOL ok = CloseHandle(handle);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        observe("close_owned_handle", ok, error);
        if (!ok) failures++;
    }
}

static BOOL child_path(WCHAR *out, size_t capacity, const WCHAR *root, const WCHAR *leaf) {
    int written = swprintf_s(out, capacity, L"%ls\\%ls", root, leaf);
    return written > 0;
}

static HANDLE create_bytes(const WCHAR *path, const char *bytes, DWORD length) {
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BOOL ok = file != INVALID_HANDLE_VALUE;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    observe("exclusive_file_create", ok, error);
    if (!ok) { failures++; return file; }
    DWORD written = 0;
    ok = WriteFile(file, bytes, length, &written, NULL);
    error = ok ? ERROR_SUCCESS : GetLastError();
    observe("file_write", ok, error);
    require("complete_file_write", ok && written == length);
    if (!ok || written != length) {
        close_owned(file);
        return INVALID_HANDLE_VALUE;
    }
    ok = FlushFileBuffers(file);
    error = ok ? ERROR_SUCCESS : GetLastError();
    observe("regular_file_flush", ok, error);
    if (!ok) failures++;
    return file;
}

static BOOL exact_bytes(const WCHAR *path, const char *expected, DWORD length) {
    HANDLE file = CreateFileW(path, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    char data[64];
    DWORD actual = 0;
    BOOL ok = ReadFile(file, data, sizeof(data), &actual, NULL);
    BOOL same = ok && actual == length && memcmp(data, expected, length) == 0;
    close_owned(file);
    return same;
}

static BOOL same_named_file(const WCHAR *path, const BY_HANDLE_FILE_INFORMATION *expected) {
    HANDLE file = CreateFileW(path, FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    BY_HANDLE_FILE_INFORMATION actual;
    BOOL ok = GetFileInformationByHandle(file, &actual);
    BOOL same = ok && actual.dwVolumeSerialNumber == expected->dwVolumeSerialNumber &&
                actual.nFileIndexHigh == expected->nFileIndexHigh &&
                actual.nFileIndexLow == expected->nFileIndexLow && actual.nNumberOfLinks == 1 &&
                (actual.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    close_owned(file);
    return same;
}

static BOOL rename_file(HANDLE file, HANDLE directory, const WCHAR *leaf,
                        const WCHAR *absolute, enum rename_method method, DWORD *error) {
    const WCHAR *name = method == WIN32_ABSOLUTE ? absolute : leaf;
    size_t characters = wcslen(name);
    if (characters == 0 || characters > 255) {
        *error = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    /* Keep the complete SDK structure, its trailing padding, and a NUL after
       the counted filename. FileNameLength still counts only name bytes. */
    size_t size = sizeof(FILE_RENAME_INFO) + (characters + 1) * sizeof(WCHAR);
    FILE_RENAME_INFO *info = (FILE_RENAME_INFO *)calloc(1, size);
    if (info == NULL) { *error = ERROR_OUTOFMEMORY; return FALSE; }
    info->ReplaceIfExists = FALSE;
    info->RootDirectory = method == WIN32_ABSOLUTE ? NULL : directory;
    info->FileNameLength = (DWORD)(characters * sizeof(WCHAR));
    memcpy(info->FileName, name, info->FileNameLength);
    BOOL ok;
    if (method == NT_RELATIVE) {
        IO_STATUS_BLOCK status_block = { 0 };
        NTSTATUS status = NtSetInformationFile(file, &status_block, info, (ULONG)size,
                                               (FILE_INFORMATION_CLASS)10);
        if (printf("{\"operation\":\"native_rename_status\",\"ntstatus\":%lu,\"io_status\":%lu}\n",
                   (unsigned long)status, (unsigned long)status_block.Status) < 0) failures++;
        ok = status == 0 && status_block.Status == 0;
        *error = ok ? ERROR_SUCCESS : RtlNtStatusToDosError(status == 0 ? status_block.Status : status);
    } else {
        ok = SetFileInformationByHandle(file, FileRenameInfo, info, (DWORD)size);
        *error = ok ? ERROR_SUCCESS : GetLastError();
    }
    free(info);
    return ok;
}

static void pin_directory_control(const WCHAR *root) {
    WCHAR path[MAX_PATH], renamed[MAX_PATH];
    if (!child_path(path, MAX_PATH, root, L"pin-control") ||
        !child_path(renamed, MAX_PATH, root, L"pin-control-moved")) {
        require("bounded_pin_control_paths", FALSE);
        return;
    }
    BOOL ok = CreateDirectoryW(path, NULL);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    observe("pin_control_directory_create", ok, error);
    if (!ok) { failures++; return; }
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok = handle != INVALID_HANDLE_VALUE;
    error = ok ? ERROR_SUCCESS : GetLastError();
    observe("pin_control_handle_open", ok, error);
    if (!ok) { failures++; return; }
    ok = MoveFileExW(path, renamed, 0);
    error = ok ? ERROR_SUCCESS : GetLastError();
    observe("rename_pinned_parent_attempt", ok, error);
    require("parent_rename_refused_with_sharing_violation", !ok && error == ERROR_SHARING_VIOLATION);
    close_owned(handle);
    if (ok) return; /* Preserve an unexpected rename; do not repair the fixture. */
    ok = MoveFileExW(path, renamed, 0);
    error = ok ? ERROR_SUCCESS : GetLastError();
    observe("rename_parent_after_handle_close", ok, error);
    if (!ok) failures++;
}

static BOOL lock_contended(const WCHAR *path) {
    HANDLE probe = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (probe == INVALID_HANDLE_VALUE) return FALSE;
    OVERLAPPED overlap = { 0 };
    BOOL locked = LockFileEx(probe, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                             0, MAXDWORD, MAXDWORD, &overlap);
    DWORD error = locked ? ERROR_SUCCESS : GetLastError();
    if (locked) {
        BOOL released = UnlockFileEx(probe, 0, MAXDWORD, MAXDWORD, &overlap);
        require("unexpected_probe_lock_released", released);
    }
    close_owned(probe);
    return !locked && error == ERROR_LOCK_VIOLATION;
}

static void directory_publication_control(const WCHAR *root, HANDLE parent, enum rename_method method) {
    WCHAR staging[MAX_PATH], existing[MAX_PATH], published[MAX_PATH], child[MAX_PATH], published_child[MAX_PATH];
    require("bounded_directory_publication_paths",
            child_path(staging, MAX_PATH, root, L"staging-tree") &&
            child_path(existing, MAX_PATH, root, L"existing-tree") &&
            child_path(published, MAX_PATH, root, L"published-tree") &&
            child_path(child, MAX_PATH, staging, L"locked-state.bin") &&
            child_path(published_child, MAX_PATH, published, L"locked-state.bin"));
    if (failures) return;
    require("fresh_directory_publication_trees", CreateDirectoryW(staging, NULL) && CreateDirectoryW(existing, NULL));
    if (failures) return;
    const char bytes[] = "public-locked-state";
    HANDLE state = create_bytes(child, bytes, sizeof(bytes));
    HANDLE directory = CreateFileW(staging, GENERIC_READ | GENERIC_WRITE | DELETE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    require("staging_tree_handle_open", directory != INVALID_HANDLE_VALUE);
    if (state != INVALID_HANDLE_VALUE && directory != INVALID_HANDLE_VALUE) {
        OVERLAPPED overlap = { 0 };
        BOOL locked = LockFileEx(state, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                                 0, MAXDWORD, MAXDWORD, &overlap);
        require("state_lifetime_lock_acquired", locked);
        if (locked) {
            require("state_lock_excludes_other_handle_before_publication", lock_contended(child));
            HANDLE duplicate = INVALID_HANDLE_VALUE;
            BOOL copied = DuplicateHandle(GetCurrentProcess(), state, GetCurrentProcess(),
                                           &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);
            require("plain_state_handle_duplicated", copied);
            if (copied) close_owned(duplicate);
            require("state_lock_survives_plain_duplicate_close", lock_contended(child));
            BY_HANDLE_FILE_INFORMATION identity;
            BOOL identity_ok = GetFileInformationByHandle(state, &identity);
            require("locked_state_identity_observed", identity_ok);
            DWORD error = ERROR_SUCCESS;
            BOOL renamed = rename_file(directory, parent, L"existing-tree", existing, method, &error);
            observe("directory_existing_destination_attempt", renamed, error);
            require("directory_existing_destination_refused", !renamed && (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS));
            require("staging_child_identity_after_collision", identity_ok && same_named_file(child, &identity));
            renamed = rename_file(directory, parent, L"published-tree", published, method, &error);
            observe("directory_publish_with_open_locked_child", renamed, error);
            if (!renamed) failures++;
            if (renamed) {
                require("published_child_is_original_file", identity_ok && same_named_file(published_child, &identity));
                require("state_lock_excludes_other_handle_after_publication", lock_contended(published_child));
                require("published_tree_sync", FlushFileBuffers(directory));
                require("published_tree_parent_sync", FlushFileBuffers(parent));
            }
            BOOL released = UnlockFileEx(state, 0, MAXDWORD, MAXDWORD, &overlap);
            require("original_state_lock_released", released);
            if (renamed && released) require("published_child_bytes_after_unlock", exact_bytes(published_child, bytes, sizeof(bytes)));
        }
    }
    close_owned(directory);
    close_owned(state);
}

int wmain(int argc, WCHAR **argv) {
    if (argc != 3) { fputs("expected a new disposable fixture directory and rename method\n", stderr); return 2; }
    enum rename_method method;
    if (wcscmp(argv[2], L"win32-relative") == 0) method = WIN32_RELATIVE;
    else if (wcscmp(argv[2], L"win32-absolute") == 0) method = WIN32_ABSOLUTE;
    else if (wcscmp(argv[2], L"nt-relative") == 0) method = NT_RELATIVE;
    else { fputs("unknown rename method\n", stderr); return 2; }
    BOOL ok = CreateDirectoryW(argv[1], NULL);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    observe("fresh_fixture_directory", ok, error);
    if (!ok) return 2; /* Never reuse or remove a pre-existing directory. */

    WCHAR volume[MAX_PATH], filesystem[64];
    ok = GetVolumePathNameW(argv[1], volume, MAX_PATH);
    if (ok) ok = GetVolumeInformationW(volume, NULL, 0, NULL, NULL, NULL, filesystem, 64);
    require("filesystem_metadata_available", ok);
    if (!ok) return 2;
    observe("filesystem_is_ntfs", wcscmp(filesystem, L"NTFS") == 0, ERROR_NOT_SUPPORTED);

    const DWORD access[] = { GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE,
                             FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE };
    const char *open_names[] = { "directory_open_read", "directory_open_write",
                                "directory_open_read_write", "directory_open_attributes" };
    const char *flush_names[] = { "directory_flush_read", "directory_flush_write",
                                 "directory_flush_read_write", "directory_flush_attributes" };
    for (size_t i = 0; i < sizeof(access) / sizeof(access[0]); i++) {
        HANDLE dir = CreateFileW(argv[1], access[i],
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 NULL, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        ok = dir != INVALID_HANDLE_VALUE;
        error = ok ? ERROR_SUCCESS : GetLastError();
        observe(open_names[i], ok, error);
        if (ok) {
            ok = FlushFileBuffers(dir);
            error = ok ? ERROR_SUCCESS : GetLastError();
            observe(flush_names[i], ok, error);
            close_owned(dir);
        }
    }

    pin_directory_control(argv[1]);
    WCHAR source[MAX_PATH], target[MAX_PATH], published[MAX_PATH];
    require("bounded_fixture_paths", child_path(source, MAX_PATH, argv[1], L"source.bin") &&
            child_path(target, MAX_PATH, argv[1], L"existing.bin") &&
            child_path(published, MAX_PATH, argv[1], L"published.bin"));
    if (failures) return 2;
    const char source_bytes[] = "public-source-bytes";
    const char target_bytes[] = "public-existing-bytes";
    HANDLE src = create_bytes(source, source_bytes, sizeof(source_bytes));
    HANDLE dst = create_bytes(target, target_bytes, sizeof(target_bytes));
    HANDLE parent = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok = parent != INVALID_HANDLE_VALUE;
    error = ok ? ERROR_SUCCESS : GetLastError();
    observe("parent_open_without_delete_sharing", ok, error);
    if (!ok) failures++;
    if (src != INVALID_HANDLE_VALUE && dst != INVALID_HANDLE_VALUE && ok) {
        BY_HANDLE_FILE_INFORMATION before, after;
        BOOL before_ok = GetFileInformationByHandle(src, &before);
        require("original_file_identity_observed", before_ok);
        ok = rename_file(src, parent, L"existing.bin", target, method, &error);
        observe("rename_existing_attempt", ok, error);
        require("existing_destination_refused", !ok && (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS));
        require("refused_source_bytes_preserved", exact_bytes(source, source_bytes, sizeof(source_bytes)));
        require("refused_destination_bytes_preserved", exact_bytes(target, target_bytes, sizeof(target_bytes)));

        ok = rename_file(src, parent, L"published.bin", published, method, &error);
        observe("rename_absent_attempt", ok, error);
        if (!ok) failures++;
        if (ok) {
            BOOL after_ok = GetFileInformationByHandle(src, &after);
            require("same_open_file_identity_after_rename", before_ok && after_ok &&
                    before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                    before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow);
            require("published_name_is_original_single_link_file", before_ok && same_named_file(published, &before));
            DWORD old_attributes = GetFileAttributesW(source);
            DWORD old_error = old_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
            require("old_source_name_absent", old_attributes == INVALID_FILE_ATTRIBUTES && old_error == ERROR_FILE_NOT_FOUND);
            require("published_bytes_match", exact_bytes(published, source_bytes, sizeof(source_bytes)));
            ok = FlushFileBuffers(src);
            error = ok ? ERROR_SUCCESS : GetLastError();
            observe("published_open_file_flush", ok, error);
            if (!ok) failures++;
            ok = FlushFileBuffers(parent);
            error = ok ? ERROR_SUCCESS : GetLastError();
            observe("same_pinned_parent_flush_after_publication", ok, error);
            if (!ok) failures++;
        }
    }
    /* The directory sequence depends on a working no-replacement file route.
       Failed file controls already make this invocation fail; no fallback. */
    if (failures == 0) directory_publication_control(argv[1], parent, method);
    close_owned(parent);
    close_owned(dst);
    close_owned(src);
    if (printf("{\"observations_completed\":%s,\"control_failures\":%d,\"power_loss_tested\":false,\"product_qualification\":false}\n",
               failures == 0 ? "true" : "false", failures) < 0) return 2;
    if (fflush(stdout) != 0) return 2;
    return failures == 0 ? 0 : 1;
}
