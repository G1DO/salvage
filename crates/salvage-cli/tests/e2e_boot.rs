use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    fixture_path(&format!("images/{}", name))
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "salvage-e2e-boot-{}-{}-{}",
        label,
        std::process::id(),
        nanos
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

fn write_v2_with_digest(
    base_name: &str,
    new_digest: &str,
    boot_secs: Option<i64>,
    out_dir: &Path,
) -> PathBuf {
    let base_path = fixture_path(base_name);
    let text = fs::read_to_string(&base_path).unwrap();
    let old_hex = "e22a313ea41b0ce4bc1919997a651a41fc0ae71eaf7d605bc2cbfd03e0a32cb8";
    let new_hex = new_digest.trim_start_matches("sha256:");
    let mut out = text.replace(old_hex, new_hex);
    if let Some(secs) = boot_secs {
        let old_boot = "\"boot_seconds\": 60";
        let new_boot = "\"boot_seconds\": ".to_owned() + &secs.to_string();
        out = out.replace(old_boot, &new_boot);
    }
    let out_path = out_dir.join("manifest-v2-test.json");
    fs::write(&out_path, out).unwrap();
    out_path
}

fn docker_ps_filtered(filter: &str) -> String {
    run_docker(&["ps", "-a", "--filter", filter, "--format", "{{.ID}}"]).unwrap_or_default()
}

fn require_docker() -> bool {
    if std::env::var("SALVAGE_TEST_DOCKER").as_deref() != Ok("1") {
        eprintln!("skipping docker boot E2E");
        return false;
    }
    true
}
#[test]
#[ignore]
fn happy_verified_with_artifact() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let ctx_dir = image_context("tiny-http");
    let digest = ensure_image(&ctx_dir, tag).expect("build tiny-http");
    assert!(digest.starts_with("sha256:"));
    let tmp = unique_temp_dir("happy-boot");
    let manifest_path =
        write_v2_with_digest("manifest-valid-v2-boot-tcp.json", &digest, None, &tmp);
    let dump_src = fixture_path("valid-pg16-custom.dump");
    let dump_dst = tmp.join("backup.dump");
    fs::copy(&dump_src, &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("boot-happy-{}", std::process::id());
    let out = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            dump_dst.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--run-id",
            run_id.as_str(),
        ])
        .output()
        .expect("run salvage");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("verified"));
    let evidence_text = fs::read_to_string(run_dir.join("evidence.json")).unwrap();
    assert!(evidence_text.contains(&digest));
    assert!(evidence_text.contains("artifact"));
    let filter = format!("name=salvage-{}", run_id);
    let ps = docker_ps_filtered(&filter);
    assert!(ps.trim().is_empty());
    assert!(!run_dir.join("postgres").exists());
    let _ = fs::remove_dir_all(&tmp);
}
#[test]
#[ignore]
fn wrong_digest_fails_boot() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-http:test";
    let ctx_dir = image_context("tiny-http");
    let _real = ensure_image(&ctx_dir, tag).expect("build tiny-http");
    let fake = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let tmp = unique_temp_dir("wrong-digest");
    let manifest_path = write_v2_with_digest("manifest-valid-v2-boot-tcp.json", fake, None, &tmp);
    let dump_src = fixture_path("valid-pg16-custom.dump");
    let dump_dst = tmp.join("backup.dump");
    fs::copy(&dump_src, &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("boot-wrong-{}", std::process::id());
    let out = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            dump_dst.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--run-id",
            run_id.as_str(),
        ])
        .output()
        .expect("run salvage");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("app/digest-mismatch"));
    assert!(stderr.contains("boot"));
    let filter = format!("name=salvage-{}", run_id);
    let ps = docker_ps_filtered(&filter);
    assert!(ps.trim().is_empty());
    let _ = fs::remove_dir_all(&tmp);
}
#[test]
#[ignore]
fn crash_cmd_false_is_app_crash() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-crash:test";
    let ctx_dir = image_context("tiny-crash");
    let digest = ensure_image(&ctx_dir, tag).expect("build crash");
    let tmp = unique_temp_dir("crash-boot");
    let manifest_path =
        write_v2_with_digest("manifest-valid-v2-boot-tcp.json", &digest, None, &tmp);
    let dump_src = fixture_path("valid-pg16-custom.dump");
    let dump_dst = tmp.join("backup.dump");
    fs::copy(&dump_src, &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("boot-crash-{}", std::process::id());
    let out = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            dump_dst.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--run-id",
            run_id.as_str(),
        ])
        .output()
        .expect("run salvage");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("app/crash"));
    let filter = format!("name=salvage-{}", run_id);
    let ps = docker_ps_filtered(&filter);
    assert!(ps.trim().is_empty());
    let _ = fs::remove_dir_all(&tmp);
}
#[test]
#[ignore]
fn hang_sleep_times_out() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-hang:test";
    let ctx_dir = image_context("tiny-hang");
    let digest = ensure_image(&ctx_dir, tag).expect("build hang");
    let tmp = unique_temp_dir("hang-boot");
    let manifest_path =
        write_v2_with_digest("manifest-valid-v2-boot-tcp.json", &digest, Some(5), &tmp);
    let dump_src = fixture_path("valid-pg16-custom.dump");
    let dump_dst = tmp.join("backup.dump");
    fs::copy(&dump_src, &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("boot-hang-{}", std::process::id());
    let out = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            dump_dst.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--run-id",
            run_id.as_str(),
        ])
        .output()
        .expect("run salvage");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("timed-out") || stderr.contains("timeout"));
    assert!(stderr.contains("boot"));
    let filter = format!("name=salvage-{}", run_id);
    let ps = docker_ps_filtered(&filter);
    assert!(ps.trim().is_empty());
    let _ = fs::remove_dir_all(&tmp);
}
#[test]
#[ignore]
fn sigint_mid_boot_cancels() {
    if !require_docker() {
        return;
    }
    let tag = "salvage-tiny-hang:test";
    let ctx_dir = image_context("tiny-hang");
    let digest = ensure_image(&ctx_dir, tag).expect("build hang");
    let tmp = unique_temp_dir("sigint-boot");
    let manifest_path =
        write_v2_with_digest("manifest-valid-v2-boot-tcp.json", &digest, Some(60), &tmp);
    let dump_src = fixture_path("valid-pg16-custom.dump");
    let dump_dst = tmp.join("backup.dump");
    fs::copy(&dump_src, &dump_dst).unwrap();
    let run_dir = tmp.join("run");
    let run_id = format!("boot-sigint-{}", std::process::id());
    let child = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            dump_dst.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--run-id",
            run_id.as_str(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let pid = child.id() as libc::pid_t;
    std::thread::sleep(std::time::Duration::from_millis(5000));
    unsafe {
        libc::kill(pid, libc::SIGINT);
    }
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cancelled"));
    let filter = format!("name=salvage-{}", run_id);
    let ps = docker_ps_filtered(&filter);
    assert!(ps.trim().is_empty());
    assert!(!run_dir.join("postgres").exists());
    let _ = fs::remove_dir_all(&tmp);
}
