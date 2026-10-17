use super::*;
use crate::scan_report_to_json;

fn read_path(path: &Path) -> std::io::Result<String> {
    let directory =
        Dir::open_ambient_dir(path.parent().expect("test parent"), ambient_authority())?;
    read_code_file(&directory, path.file_name().expect("test filename"))
}

#[test]
fn scan_reports_missing_root_as_incomplete() {
    let report = scan(Path::new("/definitely/not/q-periapt/missing"));
    assert!(report.findings.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "metadata"
    );
}

fn scratch_dir(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("q-periapt-cli-{tag}-"))
        .tempdir()
        .expect("create owned scanner fixture")
}

#[test]
fn code_reader_rejects_growth_after_metadata_admission() {
    use std::io::Write;
    let fixture = scratch_dir("reader-growth");
    let dir = fixture.path();
    let path = dir.join("changing.rs");
    std::fs::write(&path, "a").expect("prepare or read scanner fixture");
    let admitted = std::fs::symlink_metadata(&path).expect("prepare or read scanner fixture");
    assert_eq!(admitted.len(), 1);
    // Reproduce a writer growing the same file after the scanner's size
    // preflight, before the actual content read. No filesystem timing race.
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("prepare or read scanner fixture");
    writer
        .write_all(&vec![b'x'; 2 * 1024 * 1024])
        .expect("prepare or read scanner fixture");
    drop(writer);
    let result = read_path(&path);
    assert!(
        result.is_err(),
        "reader accepted a file beyond its 2 MiB limit"
    );
    assert_eq!(
        result.expect_err("scanner must reject this input").kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn scan_accepts_exact_byte_limit_and_rejects_one_extra_byte() {
    let fixture = scratch_dir("reader-limit");
    let dir = fixture.path();
    let path = dir.join("limit.rs");
    // Use multibyte UTF-8 and a finding at the very end: the limit counts
    // bytes, and a successful scan must include the full permitted input.
    let text = "\u{00e9}".repeat((2 * 1024 * 1024 - 4) / 2) + "\nrsa";
    std::fs::write(&path, &text).expect("prepare or read scanner fixture");
    assert_eq!(
        read_path(&path).expect("prepare or read scanner fixture"),
        text
    );
    let report = scan(&path);
    assert!(report.errors.is_empty());
    assert!(report
        .findings
        .iter()
        .any(|f| f.token == "rsa" && f.line == 2));
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(true))
    );

    std::fs::write(&path, text + "x").expect("prepare or read scanner fixture");
    assert_eq!(
        read_path(&path)
            .expect_err("scanner must reject this input")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    let report = scan(&path);
    assert!(report.findings.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "too_large"
    );
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn scan_rejects_invalid_utf8_instead_of_scanning_a_partial_file() {
    let fixture = scratch_dir("reader-utf8");
    let dir = fixture.path();
    let path = dir.join("invalid.rs");
    std::fs::write(&path, b"rsa\n\xff").expect("prepare or read scanner fixture");
    assert_eq!(
        read_path(&path)
            .expect_err("scanner must reject this input")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    let report = scan(&path);
    assert!(report.findings.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "read_file"
    );
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[cfg(unix)]
#[test]
fn scan_records_symlink_as_error_so_report_is_incomplete() {
    let fixture = scratch_dir("symlink");
    let dir = fixture.path();
    std::fs::write(dir.join("real.rs"), "use rsa::Pkcs1v15;\n")
        .expect("prepare or read scanner fixture");
    let link = dir.join("link.rs");
    std::os::unix::fs::symlink(dir.join("real.rs"), &link)
        .expect("prepare or read scanner fixture");

    let report = scan(dir);
    assert!(report.findings.iter().any(|f| f.token == "rsa"));
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "symlink_skipped"
    );
    assert_eq!(
        report.errors.first().expect("one scan error").path,
        link.display().to_string()
    );
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn scan_never_skips_the_explicitly_named_root() {
    let fixture = scratch_dir("root-skip");
    let parent = fixture.path();
    for name in ["target", ".config"] {
        let root = parent.join(name);
        std::fs::create_dir(&root).expect("prepare or read scanner fixture");
        std::fs::write(root.join("legacy.rs"), "let s = ecdsa_sign();\n")
            .expect("prepare or read scanner fixture");
        // A skip-listed descendant is still pruned.
        let nested = root.join("target");
        std::fs::create_dir(&nested).expect("prepare or read scanner fixture");
        std::fs::write(nested.join("gen.rs"), "let h = Md5::new();\n")
            .expect("prepare or read scanner fixture");

        let report = scan(&root);
        assert!(
            report.errors.is_empty(),
            "scan of root {name:?} hit errors: {:?}",
            report.errors
        );
        assert!(
            report.findings.iter().any(|f| f.token == "ecdsa"),
            "root {name:?} must be scanned even though it matches the skip rules"
        );
        assert!(
            !report.findings.iter().any(|f| f.token == "md5"),
            "descendant skip dirs under root {name:?} must still be pruned"
        );
    }
}

#[cfg(any(unix, windows))]
fn file_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("create file symlink fixture");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).expect("create file symlink fixture");
}

#[cfg(any(unix, windows))]
fn directory_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("create directory symlink fixture");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(target, link).expect("create directory symlink fixture");
}

#[cfg(any(unix, windows))]
#[test]
fn file_replacement_after_metadata_cannot_read_outside_the_tree() {
    let fixture = tempfile::tempdir().expect("prepare or read scanner fixture");
    let root = fixture.path().join("tree");
    std::fs::create_dir(&root).expect("prepare or read scanner fixture");
    let outside = fixture.path().join("outside.rs");
    std::fs::write(&outside, "rsa OUTSIDE_SYNTHETIC_MARKER\n")
        .expect("prepare or read scanner fixture");
    let path = root.join("code.rs");
    std::fs::write(&path, "ordinary code\n").expect("prepare or read scanner fixture");
    let parent =
        Dir::open_ambient_dir(&root, ambient_authority()).expect("prepare or read scanner fixture");
    let metadata = parent
        .symlink_metadata("code.rs")
        .expect("prepare or read scanner fixture");
    assert!(metadata.is_file());
    std::fs::remove_file(&path).expect("prepare or read scanner fixture");
    file_symlink(&outside, &path);

    let mut report = ScanReport::default();
    scan_admitted_entry(
        &parent,
        OsStr::new("code.rs"),
        &path,
        metadata,
        &mut report,
        false,
    );
    assert!(
        report.findings.is_empty(),
        "read replacement target contents"
    );
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "read_file"
    );
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[cfg(any(unix, windows))]
#[test]
fn directory_replacement_after_metadata_cannot_escape_the_tree() {
    let fixture = tempfile::tempdir().expect("prepare or read scanner fixture");
    let root = fixture.path().join("tree");
    let path = root.join("nested");
    let outside = fixture.path().join("outside");
    std::fs::create_dir_all(&path).expect("prepare or read scanner fixture");
    std::fs::create_dir(&outside).expect("prepare or read scanner fixture");
    std::fs::write(outside.join("secret.rs"), "rsa OUTSIDE_SYNTHETIC_MARKER\n")
        .expect("prepare or read scanner fixture");
    let parent =
        Dir::open_ambient_dir(&root, ambient_authority()).expect("prepare or read scanner fixture");
    let metadata = parent
        .symlink_metadata("nested")
        .expect("prepare or read scanner fixture");
    assert!(metadata.is_dir());
    std::fs::rename(&path, root.join("original-nested")).expect("prepare or read scanner fixture");
    directory_symlink(&outside, &path);

    let mut report = ScanReport::default();
    scan_admitted_entry(
        &parent,
        OsStr::new("nested"),
        &path,
        metadata,
        &mut report,
        false,
    );
    assert!(report.findings.is_empty(), "enumerated replacement target");
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "read_dir"
    );
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn opened_directory_is_not_retargeted_when_its_path_changes() -> std::io::Result<()> {
    let fixture = tempfile::tempdir().expect("prepare or read scanner fixture");
    let path = fixture.path().join("selected");
    std::fs::create_dir(&path).expect("prepare or read scanner fixture");
    std::fs::write(path.join("original.rs"), "ecdsa ORIGINAL\n")
        .expect("prepare or read scanner fixture");
    let parent = Dir::open_ambient_dir(fixture.path(), ambient_authority())
        .expect("prepare or read scanner fixture");
    let selected = parent
        .open_dir_nofollow("selected")
        .expect("prepare or read scanner fixture");
    let moved = fixture.path().join("moved");
    let rename_blocked = match std::fs::rename(&path, &moved) {
        Ok(()) => {
            std::fs::create_dir(&path)?;
            std::fs::write(path.join("replacement.rs"), "rsa REPLACEMENT\n")?;
            false
        }
        // A Windows directory handle may deny DELETE sharing. ERROR_SHARING_VIOLATION
        // (32) is not mapped to PermissionDenied by the supported Rust toolchain.
        Err(error)
            if cfg!(windows)
                && (error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(32)) =>
        {
            true
        }
        Err(error) => return Err(error),
    };
    let mut report = ScanReport::default();
    scan_directory(&selected, &path, &mut report);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings.first().expect("one scan finding").token,
        "ecdsa"
    );
    drop(selected);
    if rename_blocked {
        // Prove the refusal was tied to the retained handle, not an unrelated
        // inability to rename this fixture: the same operation must now work.
        std::fs::rename(&path, &moved)?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifo_replacement_is_rejected_before_reading() {
    let fixture = tempfile::tempdir().expect("prepare or read scanner fixture");
    let path = fixture.path().join("code.rs");
    std::fs::write(&path, "ordinary code\n").expect("prepare or read scanner fixture");
    let parent = Dir::open_ambient_dir(fixture.path(), ambient_authority())
        .expect("prepare or read scanner fixture");
    let metadata = parent
        .symlink_metadata("code.rs")
        .expect("prepare or read scanner fixture");
    std::fs::remove_file(&path).expect("prepare or read scanner fixture");
    assert!(std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("prepare or read scanner fixture")
        .success());
    let mut report = ScanReport::default();
    scan_admitted_entry(
        &parent,
        OsStr::new("code.rs"),
        &path,
        metadata,
        &mut report,
        false,
    );
    assert!(report.findings.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.errors.first().expect("one scan error").operation,
        "read_file"
    );
    assert!(report
        .errors
        .first()
        .expect("one scan error")
        .message
        .contains("not a regular file"));
}

#[cfg(any(unix, windows))]
#[test]
fn trailing_separator_does_not_allow_a_symlink_root() {
    let fixture = tempfile::tempdir().expect("prepare or read scanner fixture");
    let target = fixture.path().join("target-directory");
    std::fs::create_dir(&target).expect("prepare or read scanner fixture");
    std::fs::write(target.join("secret.rs"), "rsa OUTSIDE_SYNTHETIC_MARKER\n")
        .expect("prepare or read scanner fixture");
    let link = fixture.path().join("link");
    directory_symlink(&target, &link);
    let report = scan(&link.join(""));
    assert!(report.findings.is_empty());
    assert!(!report.errors.is_empty());
    assert_eq!(
        scan_report_to_json(&report).get("complete"),
        Some(&serde_json::Value::Bool(false))
    );
}
