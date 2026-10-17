/* Native Windows API observations, using only disposable public test bytes. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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

static BOOL rename_relative(HANDLE file, HANDLE directory, const WCHAR *leaf, DWORD *error) {
    size_t characters = wcslen(leaf);
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
    info->RootDirectory = directory;
    info->FileNameLength = (DWORD)(characters * sizeof(WCHAR));
    memcpy(info->FileName, leaf, info->FileNameLength);
    BOOL ok = SetFileInformationByHandle(file, FileRenameInfo, info, (DWORD)size);
    *error = ok ? ERROR_SUCCESS : GetLastError();
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

int wmain(int argc, WCHAR **argv) {
    if (argc != 2) { fputs("expected a new disposable fixture directory\n", stderr); return 2; }
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
    HANDLE parent = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
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
        ok = rename_relative(src, parent, L"existing.bin", &error);
        observe("relative_rename_existing_attempt", ok, error);
        require("existing_destination_refused", !ok && (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS));
        require("refused_source_bytes_preserved", exact_bytes(source, source_bytes, sizeof(source_bytes)));
        require("refused_destination_bytes_preserved", exact_bytes(target, target_bytes, sizeof(target_bytes)));

        ok = rename_relative(src, parent, L"published.bin", &error);
        observe("relative_rename_absent_attempt", ok, error);
        if (!ok) failures++;
        if (ok) {
            BOOL after_ok = GetFileInformationByHandle(src, &after);
            require("same_open_file_identity_after_rename", before_ok && after_ok &&
                    before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                    before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow);
            require("published_bytes_match", exact_bytes(published, source_bytes, sizeof(source_bytes)));
            ok = FlushFileBuffers(src);
            error = ok ? ERROR_SUCCESS : GetLastError();
            observe("published_open_file_flush", ok, error);
            if (!ok) failures++;
        }
    }
    close_owned(parent);
    close_owned(dst);
    close_owned(src);
    if (printf("{\"observations_completed\":%s,\"control_failures\":%d,\"power_loss_tested\":false,\"product_qualification\":false}\n",
               failures == 0 ? "true" : "false", failures) < 0) return 2;
    if (fflush(stdout) != 0) return 2;
    return failures == 0 ? 0 : 1;
}
