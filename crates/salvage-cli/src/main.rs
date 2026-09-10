use std::path::{Path, PathBuf};

use salvage_core::lifecycle::{
    RunConfig, RunEngine, RunError, RunId, Verdict, install_signal_handler,
};
use salvage_core::manifest::{AnyManifest, parse_any_manifest_bytes};
use salvage_core::workspace_check;
use salvage_evidence::{EvidenceCompleteness, parse_evidence_bundle_bytes, render_html_report};
use salvage_oci::{CompositeBootExecutor, OciBootExecutor};
use salvage_postgres::PostgresStageExecutor;
use sha2::{Digest, Sha256};

const USAGE: &str = "salvage check | salvage manifest check <path> | salvage evidence check <path> | salvage evidence report <path> | salvage run <path> [--backup <path>] [--artifact <repo@sha256:...>]";

fn json_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

fn manifest_check(path: &str) -> (i32, String) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                2,
                format!(
                    r#"{{"status":"error","code":"io","message":"cannot read {}: {}"}}"#,
                    json_escape(path),
                    json_escape(&error.to_string())
                ),
            );
        }
    };
    match parse_any_manifest_bytes(&bytes) {
        Ok(any) => (
            0,
            format!(
                r#"{{"status":"ok","command":"manifest-check","schema_version":"{}","manifest_hash":"{}"}}"#,
                any.schema_version(),
                any.manifest_hash_any()
            ),
        ),
        Err(error) => (
            1,
            format!(
                r#"{{"status":"error","code":"{}","message":"{}"}}"#,
                json_escape(error.code()),
                json_escape(&error.message())
            ),
        ),
    }
}

fn evidence_check(path: &str) -> (i32, String) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                2,
                format!(
                    r#"{{"status":"error","code":"io","message":"cannot read {}: {}"}}"#,
                    json_escape(path),
                    json_escape(&error.to_string())
                ),
            );
        }
    };
    match parse_evidence_bundle_bytes(&bytes) {
        Ok(bundle) => {
            if bundle.completeness == EvidenceCompleteness::Incomplete {
                (
                    1,
                    r#"{"status":"error","code":"evidence/incomplete","message":"evidence bundle is marked incomplete"}"#
                        .to_owned(),
                )
            } else {
                (
                    0,
                    format!(
                        r#"{{"status":"ok","command":"evidence-check","schema_version":"{}","run_id":"{}","completeness":"{}","verdict_classification":"{}"}}"#,
                        json_escape(&bundle.schema_version),
                        json_escape(&bundle.run.run_id),
                        json_escape(&bundle.completeness.to_string()),
                        json_escape(&bundle.verdict_classification.to_string()),
                    ),
                )
            }
        }
        Err(error) => (
            1,
            format!(
                r#"{{"status":"error","code":"{}","message":"{}"}}"#,
                json_escape(error.code()),
                json_escape(&error.message())
            ),
        ),
    }
}

fn evidence_report(path: &str) -> (i32, String) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                2,
                format!(
                    r#"{{"status":"error","code":"io","message":"cannot read {}: {}"}}"#,
                    json_escape(path),
                    json_escape(&error.to_string())
                ),
            );
        }
    };
    match parse_evidence_bundle_bytes(&bytes) {
        Ok(bundle) => (0, render_html_report(&bundle)),
        Err(error) => (
            1,
            format!(
                r#"{{"status":"error","code":"{}","message":"{}"}}"#,
                json_escape(error.code()),
                json_escape(&error.message())
            ),
        ),
    }
}

struct RunOptions {
    manifest_path: String,
    backup_path: Option<String>,
    run_id: Option<String>,
    run_dir: Option<String>,
    expected_table: Option<String>,
    artifact: Option<String>,
}

fn parse_run_args(args: &[String]) -> Result<RunOptions, String> {
    if args.is_empty() {
        return Err("expected `<path>`".to_owned());
    }
    let manifest_path = args[0].clone();
    if manifest_path.starts_with('-') {
        return Err(format!(
            "unexpected flag `{manifest_path}` before manifest path"
        ));
    }
    let mut backup_path = None;
    let mut run_id = None;
    let mut run_dir = None;
    let mut expected_table = None;
    let mut artifact = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--backup" => {
                i += 1;
                if i >= args.len() {
                    return Err("expected path after `--backup`".to_owned());
                }
                backup_path = Some(args[i].clone());
            }
            "--run-id" => {
                i += 1;
                if i >= args.len() {
                    return Err("expected identity after `--run-id`".to_owned());
                }
                run_id = Some(args[i].clone());
            }
            "--run-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("expected path after `--run-dir`".to_owned());
                }
                run_dir = Some(args[i].clone());
            }
            "--expected-table" => {
                i += 1;
                if i >= args.len() {
                    return Err("expected table name after `--expected-table`".to_owned());
                }
                expected_table = Some(args[i].clone());
            }
            "--artifact" => {
                i += 1;
                if i >= args.len() {
                    return Err("expected digest after --artifact".to_owned());
                }
                artifact = Some(args[i].clone());
            }
            arg if !arg.starts_with('-') && backup_path.is_none() => {
                backup_path = Some(arg.to_owned());
            }
            other => {
                return Err(format!("unexpected argument `{other}`"));
            }
        }
        i += 1;
    }

    Ok(RunOptions {
        manifest_path,
        backup_path,
        run_id,
        run_dir,
        expected_table,
        artifact,
    })
}

fn resolve_backup_path(manifest_path: &Path, expected_digest: &str) -> PathBuf {
    let candidate_dirs = [
        manifest_path.parent().map(|p| p.to_path_buf()),
        std::env::current_dir().ok(),
    ];
    for dir in candidate_dirs.into_iter().flatten() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Ok(file_bytes) = std::fs::read(&path)
                {
                    let mut hasher = Sha256::new();
                    hasher.update(&file_bytes);
                    let digest = format!("sha256:{:x}", hasher.finalize());
                    if digest == expected_digest {
                        return path;
                    }
                }
            }
        }
    }
    let stem = manifest_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("backup");
    let fallback = manifest_path.with_file_name(format!("{stem}.dump"));
    if fallback.exists() {
        fallback
    } else {
        manifest_path.with_file_name("backup.dump")
    }
}

fn salvage_run(opts: RunOptions) -> (i32, String) {
    install_signal_handler();

    let bytes = match std::fs::read(&opts.manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                2,
                format!(
                    r#"{{"status":"error","code":"io","message":"cannot read {}: {}"}}"#,
                    json_escape(&opts.manifest_path),
                    json_escape(&error.to_string())
                ),
            );
        }
    };

    let any = match parse_any_manifest_bytes(&bytes) {
        Ok(any) => any,
        Err(error) => {
            return (
                1,
                format!(
                    r#"{{"status":"error","code":"{}","message":"{}"}}"#,
                    json_escape(error.code()),
                    json_escape(&error.message())
                ),
            );
        }
    };

    let schema_version = any.schema_version().to_owned();
    let manifest_hash_val = any.manifest_hash_any();
    let backup_digest = match &any {
        AnyManifest::V1(m) => m.backup.digest.clone(),
        AnyManifest::V2(m) => m.backup.digest.clone(),
    };
    let run_owner = match &any {
        AnyManifest::V1(m) => m.run.owner.clone(),
        AnyManifest::V2(m) => m.run.owner.clone(),
    };
    if let Some(ref flag) = opts.artifact {
        match &any {
            AnyManifest::V1(_) => {
                return (
                    2,
                    r#"{{"status":"error","code":"usage","message":"artifact flag requires v2 manifest"}}"#.to_owned(),
                );
            }
            AnyManifest::V2(m) => {
                let want = if let Some(pos) = flag.rfind(64 as char) {
                    flag[pos + 1..].to_owned()
                } else {
                    flag.clone()
                };
                if want != m.app.digest {
                    return (
                        1,
                    r#"{{"status":"error","code":"app/digest-mismatch","message":"artifact digest mismatch"}}"#.to_owned(),
                    );
                }
            }
        }
    }

    let backup_path = match opts.backup_path {
        Some(path) => PathBuf::from(path),
        None => resolve_backup_path(Path::new(&opts.manifest_path), &backup_digest),
    };

    let run_id = match opts.run_id {
        Some(id_str) => match RunId::new(id_str) {
            Ok(id) => id,
            Err(err) => {
                return (
                    1,
                    format!(
                        r#"{{"status":"error","code":"run/invalid-id","message":"{}"}}"#,
                        json_escape(&err.to_string())
                    ),
                );
            }
        },
        None => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            RunId::new(format!("{}-{nanos}", run_owner)).unwrap()
        }
    };

    let run_dir = match opts.run_dir {
        Some(dir_str) => {
            let path = PathBuf::from(dir_str);
            if path.is_relative() {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(path)
            } else {
                path
            }
        }
        None => std::env::temp_dir().join(format!("salvage-run-{run_id}")),
    };

    let config = RunConfig::new(run_id.clone(), run_dir);
    let expected_name = opts
        .expected_table
        .clone()
        .unwrap_or_else(|| "salvage_records".to_owned());
    let outcome_res = match any {
        AnyManifest::V1(manifest) => {
            let mut executor = PostgresStageExecutor::new(backup_path);
            executor = executor.with_expected_table(expected_name);
            RunEngine::start_run(config, manifest, &mut executor)
        }
        AnyManifest::V2(manifest_v2) => {
            let pg = PostgresStageExecutor::new(backup_path).with_expected_table(expected_name);
            let oci = OciBootExecutor::new(manifest_v2.app.clone(), manifest_v2.limits.clone());
            let mut combo = CompositeBootExecutor::new(pg, oci);
            RunEngine::start_run_v2(config, manifest_v2, &mut combo)
        }
    };
    match outcome_res {
        Ok(outcome) => {
            if outcome.verdict.is_passed() && outcome.cleanup_status.is_success() {
                (
                    0,
                    format!(
                        r#"{{"status":"ok","command":"run","run_id":"{}","schema_version":"{}","manifest_hash":"{}","verdict":"passed","verdict_classification":"verified","cleanup_status":"success"}}"#,
                        json_escape(run_id.as_str()),
                        json_escape(&schema_version),
                        manifest_hash_val,
                    ),
                )
            } else {
                let (code, message, verdict_str, stage_str) = match &outcome.verdict {
                    Verdict::Passed => (
                        "cleanup/failed".to_owned(),
                        "cleanup failed after verification".to_owned(),
                        "passed",
                        "cleaning".to_owned(),
                    ),
                    Verdict::Failed {
                        stage,
                        code,
                        message,
                    } => (code.clone(), message.clone(), "failed", stage.to_string()),
                    Verdict::TimedOut {
                        stage,
                        timeout_seconds,
                    } => (
                        "timeout".to_owned(),
                        format!("stage timed out after {timeout_seconds}s"),
                        "timed-out",
                        stage.to_string(),
                    ),
                    Verdict::Cancelled { stage, reason, .. } => (
                        "cancelled".to_owned(),
                        reason.clone(),
                        "cancelled",
                        stage.to_string(),
                    ),
                };
                let cleanup_str = if outcome.cleanup_status.is_success() {
                    "success"
                } else {
                    "failed"
                };
                (
                    1,
                    format!(
                        r#"{{"status":"error","command":"run","code":"{}","message":"{}","verdict":"{}","stage":"{}","cleanup_status":"{}"}}"#,
                        json_escape(&code),
                        json_escape(&message),
                        verdict_str,
                        stage_str,
                        cleanup_str,
                    ),
                )
            }
        }
        Err(RunError::AlreadyExists { run_id }) => (
            1,
            format!(
                r#"{{"status":"error","code":"run/already-exists","message":"run `{}` already completed in this directory"}}"#,
                json_escape(run_id.as_str())
            ),
        ),
        Err(RunError::StaleResources { run_id, state }) => (
            1,
            format!(
                r#"{{"status":"error","code":"run/stale-resources","message":"run `{}` has stale resources from state `{}`"}}"#,
                json_escape(run_id.as_str()),
                json_escape(&state)
            ),
        ),
        Err(err) => (
            1,
            format!(
                r#"{{"status":"error","code":"run/failed","message":"{}"}}"#,
                json_escape(&err.to_string())
            ),
        ),
    }
}

fn response(args: &[String]) -> (i32, String) {
    match args {
        [command] if command == "check" => (0, workspace_check().to_json()),
        [first, second, path] if first == "manifest" && second == "check" => manifest_check(path),
        [first, second, path] if first == "evidence" && second == "check" => evidence_check(path),
        [first, second, path] if first == "evidence" && second == "report" => evidence_report(path),
        [first, rest @ ..] if first == "run" || first == "restore" => match parse_run_args(rest) {
            Ok(opts) => salvage_run(opts),
            Err(msg) => (
                2,
                format!(
                    r#"{{"status":"error","code":"usage","message":"{}: expected `{}`"}}"#,
                    json_escape(&msg),
                    USAGE
                ),
            ),
        },
        [command] if command == "--version" || command == "-V" => (
            0,
            format!(
                r#"{{"status":"ok","command":"version","version":"{}"}}"#,
                env!("CARGO_PKG_VERSION")
            ),
        ),
        [command] if command == "--help" || command == "-h" => (
            0,
            format!(r#"{{"status":"ok","command":"help","usage":"{}"}}"#, USAGE),
        ),
        _ => (
            2,
            format!(
                r#"{{"status":"error","code":"usage","message":"expected `{}`"}}"#,
                USAGE
            ),
        ),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (exit_code, output) = response(&args);

    if exit_code == 0 {
        println!("{output}");
    } else {
        eprintln!("{output}");
    }

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::{USAGE, response};

    #[test]
    fn invalid_arguments_return_a_usage_error() {
        let args = vec!["unknown-command".to_owned()];

        assert_eq!(
            response(&args),
            (
                2,
                format!(r#"{{"status":"error","code":"usage","message":"expected `{USAGE}`"}}"#)
            )
        );
    }
}
