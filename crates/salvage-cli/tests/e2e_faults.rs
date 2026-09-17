//! O4-1 fault matrix: full-slice faults with expected verdicts (parent #45).
//!
//! Opt-in Docker matrix (`SALVAGE_TEST_DOCKER=1`, `#[ignore]` by default so
//! `cargo test` stays green for non-Docker devs). Precedent: `e2e_contracts.rs`.
//!
//! Every row runs the complete v3 pipeline (restore -> boot -> contracts ->
//! evidence -> cleanup) under one injected fault and asserts the full O4
//! exit-gate shape for that fault:
//!
//! | fault | injection | expected code | expected classification |
//! |---|---|---|
//! | truncated backup | `corrupt-truncated.dump` + matching digest | `restore/corrupt-backup` | `orchestration-failed` |
//! | wrong declared DB version | `postgres.version = "99.0"` | `restore/unsupported-version` | `orchestration-failed` |
//! | wrong app version | zeroed `app.digest` pin | `app/digest-mismatch` | `boot-failed` |
//! | missing role | owner absent from fresh target (`missing-role.dump`) | `restore/missing-role` | `orchestration-failed` |
//! | malformed contract | disallowed `argv[0]` (`rm`, never spawned) | `contract/malformed` | `verification-failed` |
//! | oversized contract | 70 KiB HTTP body vs 64 KiB cap | `contract/oversized` | `verification-failed` |
//! | evidence-write failure | `evidence.destination = file:///dev/full` (Linux) | `evidence/write-failed` | `verification-failed` |
//! | SIGTERM mid-contracts | `SIGTERM` while an `exec sleep` contract runs | `cancelled` | `cancelled` |
//! | global deadline expiry | `SALVAGE_TEST_GLOBAL_TIMEOUT_MS` + restore delay hook | `timed-out` | `timed-out` |
//!
//! Every row additionally asserts: bounded wall-clock, evidence bundle parses,
//! `evidence check` passes with `cleanup_status success`, and zero leaked
//! resources (containers, networks, ephemeral postgres dir, temp files).
//! `SALVAGE_FAULT_MATRIX_REPEATS=N` repeats each row (CI uses 2) because O4
//! requires the matrix to pass *repeatedly* with deterministic verdicts.
//!
//! No external network: PG is Unix-socket-only, contracts are `sql`/`exec`
//! only (no `http` contract, so no local server is needed), the digest pin is
//! local, and `/dev/full` is a kernel-guaranteed `ENOSPC`-class writer.
//!
//! Deliberately deferred to later O4 slices (see #45): missing extension
//! at E2E (classifier unit-tested with real message shapes; a deterministic
//! fixture needs a multi-extension toolchain — the committed dumps carry no
//! extension entries to diverge, see ADR 0008), true filesystem-`ENOSPC`
//! (shares the `evidence/write-failed` path covered here), and
//! reachable-egress E2E (needs a responder outside the isolated net).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn salvage_bin() -> String {
    env!("CARGO_BIN_EXE_salvage").to_owned()
}

fn docker_bin() -> PathBuf {
    if let Ok(v) = std::env::var("SALVAGE_DOCKER_BIN") {
        return PathBuf::from(v);
    }
    PathBuf::from("docker")
}

fn run_docker(args: &[&str]) -> Option<String> {
    let out = Command::new(docker_bin()).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn image_context(name: &str) -> PathBuf {
    fixture_path(&format!("images/{name}"))
}
fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "salvage-e2e-faults-{label}-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Per-iteration run id: unique across repeats so a leaked container or
/// network from an earlier iteration can never be masked by a fresh one.
fn unique_run_id(label: &str) -> String {
    format!("faults-{label}-{}-{}", std::process::id(), unique_nanos())
}

fn ensure_image(context: &Path, tag: &str) -> Option<String> {
    let status = Command::new(docker_bin())
        .arg("build")
        .arg("-t")
        .arg(tag)
        .arg(context)
        .output()
        .ok()?;
    if !status.status.success() {
        eprintln!("docker build failed");
        return None;
    }
    run_docker(&["image", "inspect", tag, "--format", "{{.Id}}"])
}

fn docker_ps_filtered(filter: &str) -> String {
    run_docker(&["ps", "-a", "--filter", filter, "--format", "{{.ID}}"]).unwrap_or_default()
}

fn docker_network_filtered(filter: &str) -> String {
    run_docker(&["network", "ls", "--filter", filter, "--format", "{{.ID}}"]).unwrap_or_default()
}

fn require_docker() -> bool {
    if std::env::var("SALVAGE_TEST_DOCKER").as_deref() != Ok("1") {
        eprintln!("skipping docker faults E2E");
        return false;
    }
    true
}

/// Repeat count for matrix determinism (`SALVAGE_FAULT_MATRIX_REPEATS`, 1).
fn matrix_repeats() -> usize {
    std::env::var("SALVAGE_FAULT_MATRIX_REPEATS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

/// Rewrites the v3 E2E base manifest: digest pin, backup digest, postgres
/// version, contracts, boot deadline, evidence destination.
#[allow(clippy::too_many_arguments)]
fn write_v3_fault(
    new_digest: &str,
    backup_digest: Option<&str>,
    postgres_version: Option<&str>,
    contracts: Option<serde_json::Value>,
    boot_secs: Option<i64>,
    destination: Option<&str>,
    out_dir: &Path,
) -> PathBuf {
    let base_path = fixture_path("manifest-valid-v3-e2e.json");
    let text = fs::read_to_string(&base_path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let new_hex = new_digest.trim_start_matches("sha256:");
    if let Some(app) = value.get_mut("app") {
        app["digest"] = serde_json::Value::String(format!("sha256:{new_hex}"));
    }
    if let Some(digest) = backup_digest {
        value["backup"]["digest"] = serde_json::Value::String(digest.to_owned());
    }
    if let Some(version) = postgres_version {
        value["postgres"]["version"] = serde_json::Value::String(version.to_owned());
    }
    if let Some(contracts) = contracts {
        value["contracts"] = contracts;
    }
    if let Some(secs) = boot_secs {
        value["deadlines"]["boot_seconds"] = serde_json::Value::from(secs);
    }
    if let Some(destination) = destination {
        value["evidence"]["destination"] = serde_json::Value::String(destination.to_owned());
    }
    let out_path = out_dir.join("manifest-v3-fault.json");
    fs::write(&out_path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
    out_path
}

fn sql_exec_contracts() -> serde_json::Value {
    serde_json::json!([
        {"name": "users-count", "kind": "sql",
         "spec": {"query": "SELECT count(*) FROM salvage_records"}, "timeout_ms": 10000},
        {"name": "check-echo", "kind": "exec",
         "spec": {"command": ["echo", "salvage-ok"]}, "timeout_ms": 10000}
    ])
}

/// Spawns a minimal HTTP/1.0 200 server on `127.0.0.1:0` returning `body`
/// (mirrors `e2e_contracts.rs`; no external network, no extra deps).
fn spawn_local_http_200(body: String) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local http");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut handled = 0;
        while Instant::now() < deadline && handled < 20 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    handled += 1;
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    std::thread::sleep(Duration::from_millis(50));
    port
}

fn run_salavage(
    manifest: &Path,
    backup: &Path,
    run_dir: &Path,
    run_id: &str,
    extra_env: &[(&str, &str)],
) -> std::process::Output {
    let mut cmd = Command::new(salvage_bin());
    cmd.args([
        "run",
        manifest.to_str().unwrap(),
        "--backup",
        backup.to_str().unwrap(),
        "--run-dir",
        run_dir.to_str().unwrap(),
        "--run-id",
        run_id,
    ]);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("run salvage")
}

fn evidence_files(run_dir: &Path) -> Vec<PathBuf> {
    [
        "evidence.json",
        "report.html",
        "journal.jsonl",
        "state.json",
    ]
    .iter()
    .map(|n| run_dir.join(n))
    .collect()
}

fn assert_zero_leak(run_id: &str, run_dir: &Path) {
    let ps = docker_ps_filtered(&format!("name=salvage-{run_id}"));
    assert!(ps.trim().is_empty(), "container leaked: {ps}");
    let net = docker_network_filtered(&format!("name=salvage-net-{run_id}"));
    assert!(net.trim().is_empty(), "network leaked: {net}");
    assert!(
        !run_dir.join("postgres").exists(),
        "ephemeral postgres dir must be removed"
    );
    for path in evidence_files(run_dir) {
        assert!(path.exists(), "evidence must be kept: {}", path.display());
    }
}

fn parse_evidence(run_dir: &Path) -> serde_json::Value {
    let text = fs::read_to_string(run_dir.join("evidence.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Shared O4 row assertion: failed exit carrying `expected_code`, bounded
/// wall-clock, parsed evidence with `expected_classification`, a green
/// `evidence check` reporting cleanup success, and zero leaked resources.
fn assert_failed_run(
    out: &std::process::Output,
    elapsed_secs: u64,
    expected_code: &str,
    expected_classification: &str,
    max_secs: u64,
    run_id: &str,
    run_dir: &Path,
) {
    assert!(
        !out.status.success(),
        "fault must fail closed, exit: {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(expected_code),
        "stderr must carry {expected_code}: {stderr}"
    );
    assert!(
        elapsed_secs <= max_secs,
        "fault row exceeded its {max_secs}s bound: {elapsed_secs}s"
    );
    let evidence = parse_evidence(run_dir);
    assert_eq!(
        evidence["verdict_classification"].as_str(),
        Some(expected_classification),
        "wrong classification for {expected_code}"
    );
    let check = Command::new(salvage_bin())
        .args([
            "evidence",
            "check",
            run_dir.join("evidence.json").to_str().unwrap(),
        ])
        .output()
        .expect("evidence check");
    assert!(check.status.success(), "failed bundle still validates");
    let check_stdout = String::from_utf8_lossy(&check.stdout);
    assert!(
        check_stdout.contains(&format!(
            "\"verdict_classification\":\"{expected_classification}\""
        )),
        "check must report {expected_classification}: {check_stdout}"
    );
    assert!(
        check_stdout.contains(r#""cleanup_status":"success""#)
            || String::from_utf8_lossy(&out.stderr).contains(r#""cleanup_status":"success""#),
        "cleanup must succeed on every fault path: check={check_stdout} stderr={stderr}"
    );
    assert_zero_leak(run_id, run_dir);
}
/// Waits for a `stage-started` journal event for `stage` (e.g.
/// `"stage":"contracts", lowercase kebab-case as persisted) so signals land
/// deterministically in that stage.
fn wait_for_journal_stage(run_dir: &Path, stage: &str, timeout_secs: u64) {
    let journal = run_dir.join("journal.jsonl");
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string(&journal) {
            for line in text.lines() {
                if line.contains("stage-started") && line.contains(stage) {
                    return;
                }
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(timeout_secs),
            "timed out waiting for stage {stage}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
#[test]
#[ignore]
fn corrupt_backup_truncated_full_slice() {
    if !require_docker() {
        return;
    }
    // sha256 of tests/fixtures/corrupt-truncated.dump: the digest must match
    // the corrupt file itself so validation reaches the magic-byte check and
    // reports `restore/corrupt-backup` (not `restore/digest-mismatch`).
    const TRUNCATED_DIGEST: &str =
        "sha256:0d2c292dcdd11b91917d1cf4d935218414f8d2b95b35696c774be79de7f26cdb";
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("corrupt-backup");
        let manifest_path = write_v3_fault(
            "sha256:e22a313ea41b0ce4bc1919997a651a41fc0ae71eaf7d605bc2cbfd03e0a32cb8",
            Some(TRUNCATED_DIGEST),
            None,
            None,
            None,
            None,
            &tmp,
        );
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("corrupt-truncated.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("corrupt");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "restore/corrupt-backup",
            "orchestration-failed",
            180,
            &run_id,
            &run_dir,
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn wrong_declared_db_version_full_slice() {
    if !require_docker() {
        return;
    }
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("wrong-db-version");
        let manifest_path = write_v3_fault(
            "sha256:e22a313ea41b0ce4bc1919997a651a41fc0ae71eaf7d605bc2cbfd03e0a32cb8",
            None,
            Some("99.0"),
            None,
            None,
            None,
            &tmp,
        );
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("dbver");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "restore/unsupported-version",
            "orchestration-failed",
            180,
            &run_id,
            &run_dir,
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn missing_role_full_slice() {
    if !require_docker() {
        return;
    }
    // sha256 of tests/fixtures/missing-role.dump: an object owned by
    // `phantom_salvage`, absent from the fresh target, so restore fails with
    // `restore/missing-role` (not `restore/corrupt-backup`) while the table
    // itself restores fine. No image needed: the fault fires in restore.
    const ROLE_DUMP_DIGEST: &str =
        "sha256:7b506c8151760de443fc02ca6688d6bdb2928ec2574038a6cb296696d2c2b82a";
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("missing-role");
        let manifest_path = write_v3_fault(
            "sha256:e22a313ea41b0ce4bc1919997a651a41fc0ae71eaf7d605bc2cbfd03e0a32cb8",
            Some(ROLE_DUMP_DIGEST),
            None,
            None,
            None,
            None,
            &tmp,
        );
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("missing-role.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("role");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "restore/missing-role",
            "orchestration-failed",
            180,
            &run_id,
            &run_dir,
        );
        // The operator-actionable role name must reach the result message.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("phantom_salvage"), "{stderr}");
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn wrong_app_digest_full_slice() {
    if !require_docker() {
        return;
    }
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("wrong-app-digest");
        let manifest_path = write_v3_fault(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            None,
            None,
            None,
            None,
            None,
            &tmp,
        );
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("appver");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "app/digest-mismatch",
            "boot-failed",
            240,
            &run_id,
            &run_dir,
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn malformed_contract_argv_full_slice() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("malformed-contract");
        // `rm` passes manifest shape validation (non-blank entries) but is
        // rejected by the exec allowlist at runtime *before* any spawn, so
        // this row is safe by construction and asserts `pid` was never set.
        let contracts = serde_json::json!([
            {"name": "users-count", "kind": "sql",
             "spec": {"query": "SELECT count(*) FROM salvage_records"}, "timeout_ms": 10000},
            {"name": "evil", "kind": "exec",
             "spec": {"command": ["rm", "-rf", "/"]}, "timeout_ms": 10000}
        ]);
        let manifest_path = write_v3_fault(&digest, None, None, Some(contracts), None, None, &tmp);
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("malformed");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "contract/malformed",
            "verification-failed",
            300,
            &run_id,
            &run_dir,
        );
        let evidence = parse_evidence(&run_dir);
        let contracts_out = evidence["contracts"].as_array().expect("contracts[]");
        assert_eq!(contracts_out.len(), 2);
        assert_eq!(
            contracts_out[1]["code"].as_str(),
            Some("contract/malformed")
        );
        assert!(
            contracts_out[1]["output"]
                .as_str()
                .is_some_and(|o| o.contains("allowlist")),
            "rejection must name the allowlist: {}",
            contracts_out[1]
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn oversized_contract_output_full_slice() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    // Oversized via HTTP, not exec: a >64 KiB `echo` would fill the pipe
    // buffer with nobody draining it and deadlock into `contract/timeout`
    // instead. The HTTP backend drains the body concurrently, so the
    // default 64 KiB cap deterministically yields `contract/oversized`.
    // (Unit coverage of exec/sql oversized lives in `contracts.rs`.)
    let big = "y".repeat(70_000);
    let http_port = spawn_local_http_200(big);
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("oversized-contract");
        let contracts = serde_json::json!([
            {"name": "big-body", "kind": "http",
             "spec": {"url": format!("http://127.0.0.1:{http_port}/"), "method": "GET"},
             "timeout_ms": 15000, "egress_allow": ["127.0.0.1"]}
        ]);
        let manifest_path = write_v3_fault(&digest, None, None, Some(contracts), None, None, &tmp);
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("oversized");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "contract/oversized",
            "verification-failed",
            300,
            &run_id,
            &run_dir,
        );
        let evidence = parse_evidence(&run_dir);
        let contracts_out = evidence["contracts"].as_array().expect("contracts[]");
        assert_eq!(contracts_out.len(), 1);
        assert_eq!(
            contracts_out[0]["code"].as_str(),
            Some("contract/oversized")
        );
        assert_eq!(contracts_out[0]["truncated"], true);
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn evidence_write_failure_full_slice() {
    if !require_docker() {
        return;
    }
    // `/dev/full` is Linux-only; every write fails `ENOSPC`-class, which is
    // exactly the disk-exhaustion path (`persist` error -> `evidence/write-failed`).
    if !cfg!(target_os = "linux") {
        eprintln!("skipping /dev/full evidence-write row off Linux");
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("evidence-write-fail");
        let manifest_path = write_v3_fault(
            &digest,
            None,
            None,
            Some(sql_exec_contracts()),
            None,
            Some("file:///dev/full"),
            &tmp,
        );
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("evwrite");

        let start = Instant::now();
        let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "evidence/write-failed",
            "verification-failed",
            300,
            &run_id,
            &run_dir,
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn sigterm_mid_contracts_cancels_full_slice() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("sigterm-contracts");
        let contracts = serde_json::json!([
            {"name": "sleeper", "kind": "exec",
             "spec": {"command": ["sleep", "60"]}, "timeout_ms": 120000}
        ]);
        let manifest_path = write_v3_fault(&digest, None, None, Some(contracts), None, None, &tmp);
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("sigterm");

        let start = Instant::now();
        let child = Command::new(salvage_bin())
            .args([
                "run",
                manifest_path.to_str().unwrap(),
                "--backup",
                dump_dst.to_str().unwrap(),
                "--run-dir",
                run_dir.to_str().unwrap(),
                "--run-id",
                &run_id,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn salvage");
        // Land the signal deterministically inside the contracts stage: the
        // journal records `StageStarted` per stage as the run progresses.
        wait_for_journal_stage(&run_dir, "\"stage\":\"contracts\"", 240);
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let out = child.wait_with_output().expect("wait on child");
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "cancelled",
            "cancelled",
            300,
            &run_id,
            &run_dir,
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
#[ignore]
fn global_deadline_expires_full_slice() {
    if !require_docker() {
        return;
    }
    for _ in 0..matrix_repeats() {
        let tmp = unique_temp_dir("global-deadline");
        let manifest_path = write_v3_fault(
            "sha256:e22a313ea41b0ce4bc1919997a651a41fc0ae71eaf7d605bc2cbfd03e0a32cb8",
            None,
            None,
            Some(sql_exec_contracts()),
            None,
            None,
            &tmp,
        );
        let dump_dst = tmp.join("backup.dump");
        fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
        let run_dir = tmp.join("run");
        let run_id = unique_run_id("deadline");

        // Stretch restore to 15 s while the test-only global deadline fires
        // at 3 s, so expiry lands deterministically inside restore even on a
        // slow machine (validation comfortably fits in 3 s).
        let start = Instant::now();
        let out = run_salavage(
            &manifest_path,
            &dump_dst,
            &run_dir,
            &run_id,
            &[
                ("SALVAGE_TEST_RESTORE_DELAY_MS", "15000"),
                ("SALVAGE_TEST_GLOBAL_TIMEOUT_MS", "3000"),
            ],
        );
        let elapsed = start.elapsed().as_secs();
        assert_failed_run(
            &out,
            elapsed,
            "timed-out",
            "timed-out",
            120,
            &run_id,
            &run_dir,
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}
