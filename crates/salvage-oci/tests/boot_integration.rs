use std::path::PathBuf;
use std::process::Command;

use salvage_core::lifecycle::{RunConfig, RunEngine, RunId, Verdict};
use salvage_core::manifest::ManifestV2;
use salvage_oci::{ContainerRuntime, OciBootExecutor};

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

fn ensure_tiny_image() -> Option<(String, String)> {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("images")
        .join("tiny-http");
    let tag = "salvage-tiny-http:test";
    let status = Command::new(docker_bin())
        .arg("build")
        .arg("-t")
        .arg(tag)
        .arg(&fixture)
        .output()
        .ok()?;
    if !status.status.success() {
        eprintln!(
            "docker build failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return None;
    }
    let id = run_docker(&["image", "inspect", tag, "--format", "{{.Id}}"])?;
    if id.is_empty() {
        return None;
    }
    Some((tag.to_string(), id))
}

fn tiny_manifest(digest: &str) -> ManifestV2 {
    let json = format!(
        r#"{{
        "schema_version": "v2",
        "backup": {{"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
        "postgres": {{"version": "16.4"}},
        "restore": {{"source": "s3", "type": "full"}},
        "app": {{
            "digest": "{}",
            "readiness": {{"type": "tcp", "port": 8080}}
        }},
        "limits": {{"cpu_millicores": 500, "memory_mib": 512, "disk_mib": 5120}},
        "deadlines": {{"restore_seconds": 60, "verify_seconds": 60, "boot_seconds": 60}},
        "evidence": {{"destination": "file:///tmp/salvage-oci-evidence"}},
        "run": {{"owner": "oci-boot-test"}}
    }}"#,
        digest
    );
    salvage_core::manifest::parse_manifest_v2(&json).expect("valid v2 manifest")
}

#[test]
#[ignore]
fn tiny_http_boot_happy_path() {
    if std::env::var("SALVAGE_TEST_DOCKER").as_deref() != Ok("1") {
        eprintln!("skipping: set SALVAGE_TEST_DOCKER=1 to run docker boot E2E");
        return;
    }
    let rt = ContainerRuntime::discover().expect("docker must be available");
    assert!(rt.major >= 24, "docker >=24 required");
    let (_tag, digest) = ensure_tiny_image().expect("tiny image build must succeed");
    assert!(digest.starts_with("sha256:"), "digest {}", digest);
    let manifest = tiny_manifest(&digest);
    let app = manifest.app.clone();
    let limits = manifest.limits.clone();
    let run_id = RunId::new(format!("oci-boot-{}", std::process::id())).expect("run id");
    let run_id_str = run_id.as_str().to_owned();
    let run_dir = std::env::temp_dir().join(format!("salvage-oci-boot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&run_dir);
    let config = RunConfig::new(run_id, run_dir.clone());
    let mut exec = OciBootExecutor::new(app, limits);
    let outcome = RunEngine::start_run_v2(config, manifest, &mut exec).expect("run must complete");
    assert!(
        matches!(outcome.verdict, Verdict::Passed),
        "expected Passed, got {:?}",
        outcome.verdict
    );
    assert!(
        exec.observed_artifact_digest.is_some(),
        "telemetry digest must be populated"
    );
    let ps = run_docker(&[
        "ps",
        "--filter",
        &format!("name=salvage-{}", run_id_str),
        "--format",
        "{{.ID}}",
    ])
    .unwrap_or_default();
    assert!(
        ps.trim().is_empty(),
        "zero leak: expected no containers for run, got {:?}",
        ps
    );
    let _ = std::fs::remove_dir_all(&run_dir);
}

#[test]
#[ignore]
fn postgres_pinned_digest_manual() {
    if std::env::var("SALVAGE_TEST_DOCKER").as_deref() != Ok("1") {
        eprintln!("skipping manual postgres digest test");
        return;
    }
    eprintln!(
        "Manual postgres digest path: pull postgres 16, record RepoDigests, run compat check. See docs."
    );
}
