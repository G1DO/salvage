use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_salvage"))
        .args(args)
        .output()
        .expect("failed to start salvage")
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
        r#"{"status":"error","code":"usage","message":"expected `salvage check`"}"#
    );
}
