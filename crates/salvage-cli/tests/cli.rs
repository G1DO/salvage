use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_salvage"))
        .args(args)
        .output()
        .expect("failed to start salvage")
}

fn manifest_fixture(name: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("../../tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn check_emits_machine_readable_success() {
    let output = run(&["check"]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"{"status":"ok","component":"workspace","postgres_adapter":"postgres"}"#
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unsupported_command_emits_machine_readable_usage_error() {
    let output = run(&["restore"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        r#"{"status":"error","code":"usage","message":"expected `salvage check | salvage manifest check <path>`"}"#
    );
}

#[test]
fn manifest_check_prints_normalized_hash_without_restoring() {
    let path = manifest_fixture("manifest-valid-v1.json");
    let output = run(&["manifest", "check", &path]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""status":"ok""#)
            && stdout.contains(r#""command":"manifest-check""#)
            && stdout.contains(r#""manifest_hash":"sha256:"#),
        "unexpected stdout: {stdout}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn manifest_check_rejects_invalid_manifest_with_typed_code() {
    let path = manifest_fixture("manifest-invalid-v1-zero-limits.json");
    let output = run(&["manifest", "check", &path]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""status":"error""#)
            && stderr.contains(r#""code":"manifest/semantic/limits""#),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn manifest_check_reports_non_utf8_input_as_parse_error() {
    let path = std::env::temp_dir().join("salvage-non-utf8-manifest.json");
    std::fs::write(&path, b"\xff\xfe{\"schema_version\": \"v1\"}").expect("write fixture");
    let output = run(&["manifest", "check", &path.to_string_lossy()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""status":"error""#) && stderr.contains(r#""code":"manifest/parse""#),
        "unexpected stderr: {stderr}"
    );
}
