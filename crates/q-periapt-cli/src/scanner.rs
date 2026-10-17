//! Filesystem traversal for the migration scanner.
use super::{scan_text, ScanError, ScanReport, CODE_EXTS, SKIP_DIRS};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::{ambient_authority, fs::Dir, fs::Metadata, fs::OpenOptions};
use std::{ffi::OsStr, io::Read, path::Path};

const MAX_CODE_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Recursively scan `root` for legacy / quantum-vulnerable crypto.
///
/// The caller selects the root. Descendants are opened relative to retained
/// directory handles, with symbolic links refused at open time. Concurrent
/// changes do not retarget traversal through a replaced directory path; this
/// does not provide an atomic snapshot of file contents or directory membership.
#[must_use]
pub fn scan(root: &Path) -> ScanReport {
    let mut report = ScanReport::default();
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_error(&mut report, root, "metadata", error);
            return report;
        }
    };
    if metadata.is_symlink() {
        symlink_error(&mut report, root);
        return report;
    }
    if let Some(name) = root.file_name() {
        let parent = root
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        match Dir::open_ambient_dir(parent, ambient_authority()) {
            Ok(directory) => scan_entry(&directory, name, root, &mut report, true),
            Err(error) => push_error(&mut report, root, "metadata", error),
        }
    } else {
        // Roots such as /, . and .. have no final named entry. Ambient access
        // selects only this explicit root; descendants never use ambient paths.
        match Dir::open_ambient_dir(root, ambient_authority()) {
            Ok(directory) => scan_directory(&directory, root, &mut report),
            Err(error) => push_error(&mut report, root, "read_dir", error),
        }
    }
    report
}

fn push_error(
    report: &mut ScanReport,
    path: &Path,
    operation: &'static str,
    error: std::io::Error,
) {
    report.errors.push(ScanError {
        path: path.display().to_string(),
        operation,
        message: error.to_string(),
    });
}

fn symlink_error(report: &mut ScanReport, path: &Path) {
    report.errors.push(ScanError {
        path: path.display().to_string(),
        operation: "symlink_skipped",
        message: "symlink not followed; scan its target explicitly".to_string(),
    });
}

fn scan_entry(parent: &Dir, name: &OsStr, path: &Path, report: &mut ScanReport, is_root: bool) {
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_error(report, path, "metadata", error);
            return;
        }
    };
    scan_admitted_entry(parent, name, path, metadata, report, is_root);
}

fn scan_admitted_entry(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    metadata: Metadata,
    report: &mut ScanReport,
    is_root: bool,
) {
    if metadata.is_symlink() {
        symlink_error(report, path);
    } else if metadata.is_dir() {
        // Explicit roots are scanned even when their names match a skip rule.
        if !is_root
            && name
                .to_str()
                .is_some_and(|name| SKIP_DIRS.contains(&name) || name.starts_with('.'))
        {
            return;
        }
        match parent.open_dir_nofollow(name) {
            Ok(directory) => scan_directory(&directory, path, report),
            Err(error) => push_error(report, path, "read_dir", error),
        }
    } else if metadata.is_file() {
        if !path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| CODE_EXTS.contains(&extension))
        {
            return;
        }
        if metadata.len() > MAX_CODE_FILE_BYTES {
            report.errors.push(ScanError {
                path: path.display().to_string(),
                operation: "too_large",
                message: "code file exceeds 2 MiB scanner limit".to_string(),
            });
            return;
        }
        match read_code_file(parent, name) {
            Ok(text) => scan_text(&path.display().to_string(), &text, &mut report.findings),
            Err(error) => push_error(report, path, "read_file", error),
        }
    }
}

fn scan_directory(directory: &Dir, path: &Path, report: &mut ScanReport) {
    let entries = match directory.entries() {
        Ok(entries) => entries,
        Err(error) => {
            push_error(report, path, "read_dir", error);
            return;
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => names.push(entry.file_name()),
            Err(error) => push_error(report, path, "dir_entry", error),
        }
    }
    names.sort();
    for name in names {
        // `path` is only a diagnostic label. All filesystem access uses the
        // already-open parent and this single directory-entry name.
        scan_entry(directory, &name, &path.join(&name), report, false);
    }
}

fn read_code_file(parent: &Dir, name: &OsStr) -> std::io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    // A writer can replace an admitted file with a FIFO. Avoid blocking in the
    // open, then reject every non-regular object before reading any contents.
    options.nonblock(true);
    let file = parent.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "scanner input is not a regular file",
        ));
    }
    // Metadata remains a preflight: bound the actual read as well as the size
    // observed before it, so concurrent growth cannot yield a truncated success.
    let mut text = String::new();
    file.take(MAX_CODE_FILE_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_CODE_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "code file exceeds 2 MiB scanner limit",
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests;
