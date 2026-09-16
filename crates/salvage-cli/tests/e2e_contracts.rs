//! O3-5 E2E matrix: versioned contracts plus isolation prove application validity.
//!
//! Opt-in Docker matrix (`SALVAGE_TEST_DOCKER=1`, `#[ignore]` by default so
//! `cargo test` stays green for non-Docker devs). Precedent: `e2e_boot.rs`.
//!
//! - `happy_verified_with_contracts`: PG16 dump + tiny-http + 1 SQL + 1 HTTP +
//!   1 exec => `verified`, contracts all `passed`, isolation `allowed:false`.
//! - `forbidden_egress_blocked_on_isolated_network`: default-deny holds,
//!   `prod-forbidden.invalid` blocked, network cleaned.
//! - `hang_and_crash_contracts_fail_closed`: `sleep` hang => `contract/timeout`,
//!   `false` crash => `contract/crash`, verdict `verification-failed`, no leak.
//! - `redaction_canary_never_survives_evidence`: canary via SQL/HTTP/exec
//!   outputs is `[REDACTED]` in all persisted evidence, never raw.
//!
//! No external network: PG is Unix-socket-only, HTTP contracts hit a
//! test-spawned `127.0.0.1` server, egress probe uses `.invalid` (RFC 2606).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "salvage-e2e-contracts-{label}-{}-{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
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
        eprintln!("skipping docker contracts E2E");
        return false;
    }
    true
}

/// Spawns a minimal HTTP/1.0 200 server on `127.0.0.1:0` returning `body`.
///
/// Returns the ephemeral port. The server runs detached up to 90s / 20
/// requests; no external network, no extra deps.
fn spawn_local_http_200(body: &str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local http");
    let port = listener.local_addr().expect("local addr").port();
    let body = body.to_owned();
    std::thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        let mut handled = 0;
        while std::time::Instant::now() < deadline && handled < 20 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    handled += 1;
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
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

fn write_v3_with_digest_http_port(
    base_name: &str,
    new_digest: &str,
    http_port: u16,
    boot_secs: Option<i64>,
    out_dir: &Path,
) -> PathBuf {
    let base_path = fixture_path(base_name);
    let text = fs::read_to_string(&base_path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let new_hex = new_digest.trim_start_matches("sha256:");
    if let Some(app) = value.get_mut("app") {
        app["digest"] = serde_json::Value::String(format!("sha256:{new_hex}"));
    }
    if let Some(contracts) = value.get_mut("contracts").and_then(|c| c.as_array_mut()) {
        for c in contracts.iter_mut() {
            if c.get("kind").and_then(|k| k.as_str()) == Some("http") {
                c["spec"]["url"] =
                    serde_json::Value::String(format!("http://127.0.0.1:{http_port}/"));
            }
        }
    }
    if let Some(secs) = boot_secs {
        value["deadlines"]["boot_seconds"] = serde_json::Value::from(secs);
    }
    let out_path = out_dir.join("manifest-v3-test.json");
    fs::write(&out_path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
    out_path
}

fn write_v3_custom(
    base_name: &str,
    new_digest: &str,
    contracts: serde_json::Value,
    boot_secs: Option<i64>,
    out_dir: &Path,
) -> PathBuf {
    let base_path = fixture_path(base_name);
    let text = fs::read_to_string(&base_path).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let new_hex = new_digest.trim_start_matches("sha256:");
    if let Some(app) = value.get_mut("app") {
        app["digest"] = serde_json::Value::String(format!("sha256:{new_hex}"));
    }
    value["contracts"] = contracts;
    if let Some(secs) = boot_secs {
        value["deadlines"]["boot_seconds"] = serde_json::Value::from(secs);
    }
    let out_path = out_dir.join("manifest-v3-test.json");
    fs::write(&out_path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
    out_path
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

#[test]
#[ignore]
fn happy_verified_with_contracts() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    assert!(digest.starts_with("sha256:"));
    let http_port = spawn_local_http_200("salvage-ok");
    let tmp = unique_temp_dir("happy-contracts");
    let manifest_path = write_v3_with_digest_http_port(
        "manifest-valid-v3-e2e.json",
        &digest,
        http_port,
        None,
        &tmp,
    );
    let dump_dst = tmp.join("backup.dump");
    fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("contracts-happy-{}", std::process::id());

    let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("verified"));

    let evidence = parse_evidence(&run_dir);
    assert_eq!(
        evidence["verdict_classification"].as_str(),
        Some("verified")
    );
    let contracts = evidence["contracts"].as_array().expect("contracts[]");
    assert_eq!(contracts.len(), 3);
    for c in contracts {
        assert_eq!(c["status"].as_str(), Some("passed"), "{c}");
        assert!(c.get("code").is_none() || c["code"].is_null(), "{c}");
    }
    let kinds: Vec<&str> = contracts
        .iter()
        .filter_map(|c| c["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"sql"), "{kinds:?}");
    assert!(kinds.contains(&"http"), "{kinds:?}");
    assert!(kinds.contains(&"exec"), "{kinds:?}");
    assert_eq!(evidence["isolation"]["egress"]["allowed"], false);
    assert_eq!(
        evidence["isolation"]["egress"]["host"].as_str(),
        Some("prod-forbidden.invalid")
    );
    let evidence_text = fs::read_to_string(run_dir.join("evidence.json")).unwrap();
    assert!(evidence_text.contains(digest.trim_start_matches("sha256:").get(..12).unwrap_or("")));
    assert!(evidence_text.contains("artifact"));

    // `evidence check` + `report` projections stay green on v3 bundles.
    let check = Command::new(salvage_bin())
        .args([
            "evidence",
            "check",
            run_dir.join("evidence.json").to_str().unwrap(),
        ])
        .output()
        .expect("evidence check");
    assert!(check.status.success());
    let report = Command::new(salvage_bin())
        .args([
            "evidence",
            "report",
            run_dir.join("evidence.json").to_str().unwrap(),
        ])
        .output()
        .expect("evidence report");
    assert!(report.status.success());
    let html = String::from_utf8_lossy(&report.stdout);
    assert!(html.contains("VERIFIED"));
    assert!(html.contains("Recovery Contracts"));
    assert!(html.contains("Boot Isolation"));

    assert_zero_leak(&run_id, &run_dir);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
#[ignore]
fn forbidden_egress_blocked_on_isolated_network() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    let http_port = spawn_local_http_200("salvage-ok");
    let tmp = unique_temp_dir("forbidden-egress");
    let manifest_path = write_v3_with_digest_http_port(
        "manifest-valid-v3-e2e.json",
        &digest,
        http_port,
        None,
        &tmp,
    );
    let dump_dst = tmp.join("backup.dump");
    fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("contracts-egress-{}", std::process::id());

    let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let evidence = parse_evidence(&run_dir);
    let isolation = &evidence["isolation"];
    assert_eq!(isolation["egress"]["allowed"], false);
    assert_eq!(
        isolation["egress"]["host"].as_str(),
        Some("prod-forbidden.invalid")
    );
    assert!(
        isolation["egress"]["detail"]
            .as_str()
            .is_some_and(|d| !d.is_empty()),
        "probe detail must be recorded"
    );
    let network = isolation["network"].as_str().unwrap_or("");
    assert!(
        network.contains(&format!("salvage-net-{run_id}")),
        "network must be per-run isolated: {network}"
    );
    let allowlist = isolation["allowlist"].as_array().expect("allowlist");
    assert!(
        allowlist.iter().any(|e| e.as_str() == Some("127.0.0.1")),
        "allowlist union must retain declared host: {allowlist:?}"
    );
    // Reachable-despite-deny would be `isolation/egress-allowed`, never Verified.
    let text = fs::read_to_string(run_dir.join("evidence.json")).unwrap();
    assert!(!text.contains("isolation/egress-allowed"));
    assert_eq!(
        evidence["verdict_classification"].as_str(),
        Some("verified")
    );

    assert_zero_leak(&run_id, &run_dir);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
#[ignore]
fn hang_and_crash_contracts_fail_closed() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    let tmp = unique_temp_dir("hang-crash");
    let contracts = serde_json::json!([
        {"name": "hang", "kind": "exec", "spec": {"command": ["sleep", "30"]}, "timeout_ms": 200},
        {"name": "crash", "kind": "exec", "spec": {"command": ["false"]}, "timeout_ms": 5000}
    ]);
    let manifest_path =
        write_v3_custom("manifest-valid-v3-e2e.json", &digest, contracts, None, &tmp);
    let dump_dst = tmp.join("backup.dump");
    fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("contracts-hangcrash-{}", std::process::id());

    let out = run_salavage(&manifest_path, &dump_dst, &run_dir, &run_id, &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("contract/"), "{stderr}");
    assert!(stderr.contains("contracts"), "{stderr}");

    let evidence = parse_evidence(&run_dir);
    assert_eq!(
        evidence["verdict_classification"].as_str(),
        Some("verification-failed"),
        "contract failures map to verification-failed, never verified"
    );
    let contracts_out = evidence["contracts"].as_array().expect("contracts[]");
    assert_eq!(contracts_out.len(), 2);
    let codes: Vec<&str> = contracts_out
        .iter()
        .filter_map(|c| c["code"].as_str())
        .collect();
    assert!(codes.contains(&"contract/timeout"), "{codes:?}");
    assert!(codes.contains(&"contract/crash"), "{codes:?}");
    // Health/readiness passed (boot ok) but contracts fail => not verified.
    assert_eq!(evidence["isolation"]["egress"]["allowed"], false);

    let check = Command::new(salvage_bin())
        .args([
            "evidence",
            "check",
            run_dir.join("evidence.json").to_str().unwrap(),
        ])
        .output()
        .expect("evidence check");
    assert!(check.status.success(), "failed bundle still validates");

    assert_zero_leak(&run_id, &run_dir);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
#[ignore]
fn redaction_canary_never_survives_evidence() {
    if !require_docker() {
        return;
    }
    let canary = "e2e-canary-9f8e7d6c5b4a1a2b";
    let tag = "salvage-tiny-http:test";
    let digest = ensure_image(&image_context("tiny-http"), tag).expect("build tiny-http");
    let http_port = spawn_local_http_200(&format!("salvage-ok {canary}"));
    let tmp = unique_temp_dir("canary");
    let contracts = serde_json::json!([
        {"name": "users-count", "kind": "sql",
         "spec": {"query": format!("SELECT '{canary}'")}, "timeout_ms": 5000},
        {"name": "health", "kind": "http",
         "spec": {"url": format!("http://127.0.0.1:{http_port}/"), "method": "GET"},
         "timeout_ms": 5000, "egress_allow": ["127.0.0.1"]},
        {"name": "check-echo", "kind": "exec",
         "spec": {"command": ["echo", canary]}, "timeout_ms": 5000}
    ]);
    let manifest_path =
        write_v3_custom("manifest-valid-v3-e2e.json", &digest, contracts, None, &tmp);
    let dump_dst = tmp.join("backup.dump");
    fs::copy(fixture_path("valid-pg16-custom.dump"), &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("contracts-canary-{}", std::process::id());

    // Env name contains SECRET so `add_env_secrets` registers the value.
    let out = run_salavage(
        &manifest_path,
        &dump_dst,
        &run_dir,
        &run_id,
        &[("SALVAGE_E2E_SECRET_CANARY_XYZ", canary)],
    );
    assert!(
        out.status.success(),
        "redacted contracts still pass, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for path in evidence_files(&run_dir) {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(canary),
            "canary leaked in {}",
            path.display()
        );
    }
    let evidence_text = fs::read_to_string(run_dir.join("evidence.json")).unwrap();
    assert!(evidence_text.contains("[REDACTED]"));

    let report = Command::new(salvage_bin())
        .args([
            "evidence",
            "report",
            run_dir.join("evidence.json").to_str().unwrap(),
        ])
        .output()
        .expect("evidence report");
    assert!(report.status.success());
    let html = String::from_utf8_lossy(&report.stdout);
    assert!(!html.contains(canary));
    assert!(html.contains("[REDACTED]"));

    assert_zero_leak(&run_id, &run_dir);
    let _ = fs::remove_dir_all(&tmp);
}
