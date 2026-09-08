//! Deterministic static report generation for recovery evidence.
//!
//! Generates deterministic, human-readable static HTML and plain text projections
//! directly from the canonical JSON evidence bundle. Identical JSON source guarantees
//! identical byte-for-byte report output.

use crate::bundle::{EvidenceBundle, VerdictClassification};

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Renders a deterministic, self-contained HTML recovery report from an evidence bundle.
pub fn render_html_report(bundle: &EvidenceBundle) -> String {
    let classification_str = bundle.verdict_classification.to_string();
    let (badge_class, badge_label) = match bundle.verdict_classification {
        VerdictClassification::Verified => ("badge-verified", "VERIFIED"),
        VerdictClassification::VerificationFailed => ("badge-failed", "VERIFICATION FAILED"),
        VerdictClassification::OrchestrationFailed => ("badge-failed", "ORCHESTRATION FAILED"),
        VerdictClassification::CleanupFailed => ("badge-warning", "CLEANUP FAILED"),
        VerdictClassification::TimedOut => ("badge-timeout", "TIMED OUT"),
        VerdictClassification::Cancelled => ("badge-cancelled", "CANCELLED"),
        VerdictClassification::Incomplete => ("badge-incomplete", "INCOMPLETE"),
    };

    let run_id = escape_html(&bundle.run.run_id);
    let owner = escape_html(&bundle.run.owner);
    let created_at = escape_html(&bundle.run.created_at);
    let completed_at = bundle
        .run
        .completed_at
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "N/A (in-progress / incomplete)".to_owned());
    let total_duration = bundle
        .run
        .total_duration_ms
        .map(|d| format!("{d} ms"))
        .unwrap_or_else(|| "N/A".to_owned());

    let tool_name = escape_html(&bundle.tool.name);
    let tool_version = escape_html(&bundle.tool.version);

    let manifest_hash = escape_html(&bundle.manifest.canonical_hash);
    let backup_digest = escape_html(&bundle.backup.digest);
    let backup_source = escape_html(&bundle.backup.source);
    let restore_type = escape_html(&bundle.backup.restore_type);

    let declared_postgres = escape_html(&bundle.versions.declared_postgres);
    let observed_server = bundle
        .versions
        .observed_server
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "none".to_owned());
    let observed_client = bundle
        .versions
        .observed_client
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "none".to_owned());

    let cpu = bundle.limits.cpu_millicores;
    let mem = bundle.limits.memory_mib;
    let disk = bundle.limits.disk_mib;
    let restore_deadline = bundle.limits.restore_seconds;
    let verify_deadline = bundle.limits.verify_seconds;

    // Build stage rows deterministically
    let mut stages_html = String::new();
    for stage in &bundle.stages {
        let dur = stage
            .duration_ms
            .map(|d| format!("{d} ms"))
            .unwrap_or_else(|| "-".to_owned());
        stages_html.push_str(&format!(
            "<tr><td><code>{}</code></td><td><span class=\"status-tag status-{}\">{}</span></td><td>{}</td></tr>\n",
            escape_html(&stage.stage),
            escape_html(&stage.status),
            escape_html(&stage.status),
            dur
        ));
    }

    // Primary verdict info
    let verdict_html = if let Some(ref v) = bundle.verdict {
        let stage_info = v
            .stage
            .as_deref()
            .map(|s| format!(" in stage <code>{}</code>", escape_html(s)))
            .unwrap_or_default();
        let code_info = v
            .code
            .as_deref()
            .map(|c| {
                format!(
                    "<p><strong>Diagnostic code:</strong> <code>{}</code></p>",
                    escape_html(c)
                )
            })
            .unwrap_or_default();
        let msg_info = v
            .message
            .as_deref()
            .map(|m| format!("<p><strong>Detail:</strong> {}</p>", escape_html(m)))
            .unwrap_or_default();

        format!(
            "<div class=\"verdict-box\">\n<p><strong>Primary verdict:</strong> <code>{}</code>{}</p>\n{}{}\n</div>",
            escape_html(&v.verdict),
            stage_info,
            code_info,
            msg_info
        )
    } else {
        "<p><em>No terminal verdict recorded.</em></p>".to_owned()
    };

    // Cleanup info
    let cleanup_html = if let Some(ref c) = bundle.cleanup {
        let mut err_list = String::new();
        if !c.errors.is_empty() {
            err_list.push_str("<ul class=\"cleanup-errors\">\n");
            for err in &c.errors {
                err_list.push_str(&format!("<li><code>{}</code></li>\n", escape_html(err)));
            }
            err_list.push_str("</ul>\n");
        }
        format!(
            "<p><strong>Cleanup status:</strong> <code>{}</code></p>\n{}",
            escape_html(&c.status),
            err_list
        )
    } else {
        "<p><em>No cleanup record.</em></p>".to_owned()
    };

    // Telemetry
    let target_db = bundle
        .telemetry
        .target_dbname
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "N/A".to_owned());
    let command_id = bundle
        .telemetry
        .command_identity
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "N/A".to_owned());
    let verified_tables_str = if bundle.telemetry.verified_tables.is_empty() {
        "none".to_owned()
    } else {
        bundle
            .telemetry
            .verified_tables
            .iter()
            .map(|t| format!("<code>{}</code>", escape_html(t)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Events summary count
    let events_count = bundle.events.len();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Salvage Recovery Evidence &mdash; {run_id}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 24px; background: #0f172a; color: #f8fafc; line-height: 1.5; }}
.container {{ max-width: 960px; margin: 0 auto; background: #1e293b; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); padding: 32px; }}
h1, h2, h3 {{ margin-top: 0; color: #f1f5f9; }}
.header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 24px; }}
.header-titles h1 {{ font-size: 24px; margin-bottom: 4px; }}
.header-titles .subtitle {{ color: #94a3b8; font-size: 14px; margin: 0; }}
.badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 14px; letter-spacing: 0.5px; text-transform: uppercase; }}
.badge-verified {{ background: #059669; color: #ffffff; }}
.badge-failed {{ background: #dc2626; color: #ffffff; }}
.badge-warning {{ background: #d97706; color: #ffffff; }}
.badge-timeout {{ background: #b91c1c; color: #ffffff; }}
.badge-cancelled {{ background: #7c3aed; color: #ffffff; }}
.badge-incomplete {{ background: #475569; color: #ffffff; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }}
.card {{ background: #0f172a; border-radius: 6px; padding: 18px; border: 1px solid #334155; }}
.card h3 {{ font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 12px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #334155; }}
th {{ color: #94a3b8; font-weight: 600; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; background: #334155; padding: 2px 6px; border-radius: 4px; color: #38bdf8; word-break: break-all; }}
.status-tag {{ padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
.status-passed {{ background: #064e3b; color: #6ee7b7; }}
.status-failed {{ background: #7f1d1d; color: #fca5a5; }}
.status-timed-out {{ background: #7f1d1d; color: #fca5a5; }}
.status-cancelled {{ background: #581c87; color: #d8b4fe; }}
.status-running {{ background: #1e3a8a; color: #93c5fd; }}
.verdict-box {{ background: #1e1b4b; border: 1px solid #4338ca; border-radius: 6px; padding: 14px; margin-top: 10px; }}
.cleanup-errors {{ margin: 8px 0 0 0; padding-left: 20px; color: #fca5a5; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #334155; text-align: right; color: #64748b; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-titles">
      <h1>Salvage Recovery Evidence</h1>
      <p class="subtitle">Run: <code>{run_id}</code> &bull; Schema: <code>{schema_version}</code> &bull; Completeness: <code>{completeness}</code></p>
    </div>
    <div>
      <span class="badge {badge_class}">{badge_label}</span>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Run Identity &amp; Tool</h3>
      <table>
        <tr><th>Run ID</th><td><code>{run_id}</code></td></tr>
        <tr><th>Owner</th><td>{owner}</td></tr>
        <tr><th>Tool</th><td>{tool_name} v{tool_version}</td></tr>
        <tr><th>Started</th><td>{created_at}</td></tr>
        <tr><th>Completed</th><td>{completed_at}</td></tr>
        <tr><th>Duration</th><td>{total_duration}</td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Manifest &amp; Backup</h3>
      <table>
        <tr><th>Manifest Digest</th><td><code>{manifest_hash}</code></td></tr>
        <tr><th>Backup Digest</th><td><code>{backup_digest}</code></td></tr>
        <tr><th>Restore Source</th><td><code>{backup_source}</code></td></tr>
        <tr><th>Restore Type</th><td><code>{restore_type}</code></td></tr>
      </table>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Engine &amp; Binaries</h3>
      <table>
        <tr><th>Declared Postgres</th><td><code>{declared_postgres}</code></td></tr>
        <tr><th>Observed Server</th><td><code>{observed_server}</code></td></tr>
        <tr><th>Observed Client</th><td><code>{observed_client}</code></td></tr>
        <tr><th>Restore Command</th><td><code>{command_id}</code></td></tr>
        <tr><th>Target DB</th><td><code>{target_db}</code></td></tr>
        <tr><th>Verified Tables</th><td>{verified_tables_str}</td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Safety Envelope</h3>
      <table>
        <tr><th>CPU Limit</th><td>{cpu} millicores</td></tr>
        <tr><th>Memory Limit</th><td>{mem} MiB</td></tr>
        <tr><th>Disk Limit</th><td>{disk} MiB</td></tr>
        <tr><th>Restore Deadline</th><td>{restore_deadline}s</td></tr>
        <tr><th>Verify Deadline</th><td>{verify_deadline}s</td></tr>
        <tr><th>Journal Events</th><td>{events_count} recorded</td></tr>
      </table>
    </div>
  </div>

  <div class="card" style="margin-bottom: 24px;">
    <h3>Stage Execution Timeline</h3>
    <table>
      <thead>
        <tr><th>Stage</th><th>Status</th><th>Duration</th></tr>
      </thead>
      <tbody>
{stages_html}      </tbody>
    </table>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Terminal Verdict ({classification_str})</h3>
      {verdict_html}
    </div>

    <div class="card">
      <h3>Resource Cleanup</h3>
      {cleanup_html}
    </div>
  </div>

  <div class="footer">
    Generated deterministically by {tool_name} v{tool_version} from canonical JSON recovery evidence.
  </div>
</div>
</body>
</html>
"#,
        run_id = run_id,
        schema_version = escape_html(&bundle.schema_version),
        completeness = escape_html(&bundle.completeness.to_string()),
        badge_class = badge_class,
        badge_label = badge_label,
        owner = owner,
        tool_name = tool_name,
        tool_version = tool_version,
        created_at = created_at,
        completed_at = completed_at,
        total_duration = total_duration,
        manifest_hash = manifest_hash,
        backup_digest = backup_digest,
        backup_source = backup_source,
        restore_type = restore_type,
        declared_postgres = declared_postgres,
        observed_server = observed_server,
        observed_client = observed_client,
        command_id = command_id,
        target_db = target_db,
        verified_tables_str = verified_tables_str,
        cpu = cpu,
        mem = mem,
        disk = disk,
        restore_deadline = restore_deadline,
        verify_deadline = verify_deadline,
        events_count = events_count,
        stages_html = stages_html,
        classification_str = classification_str,
        verdict_html = verdict_html,
        cleanup_html = cleanup_html,
    )
}

/// Renders a deterministic ASCII plain text summary from an evidence bundle.
pub fn render_text_report(bundle: &EvidenceBundle) -> String {
    let mut out = String::new();
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(&format!(
        "SALVAGE RECOVERY EVIDENCE REPORT: {}\n",
        bundle.run.run_id
    ));
    out.push_str(&format!(
        "Classification: {}\n",
        bundle.verdict_classification
    ));
    out.push_str(&format!("Completeness:   {}\n", bundle.completeness));
    out.push_str(
        "================================================================================\n\n",
    );

    out.push_str("--- IDENTITY ---\n");
    out.push_str(&format!(
        "Tool:             {} v{}\n",
        bundle.tool.name, bundle.tool.version
    ));
    out.push_str(&format!("Owner:            {}\n", bundle.run.owner));
    out.push_str(&format!(
        "Manifest Digest:  {}\n",
        bundle.manifest.canonical_hash
    ));
    out.push_str(&format!("Backup Digest:    {}\n", bundle.backup.digest));
    out.push_str(&format!("Created At:       {}\n", bundle.run.created_at));
    if let Some(ref c) = bundle.run.completed_at {
        out.push_str(&format!("Completed At:     {}\n", c));
    }
    if let Some(d) = bundle.run.total_duration_ms {
        out.push_str(&format!("Total Duration:   {} ms\n", d));
    }
    out.push('\n');

    out.push_str("--- VERSIONS ---\n");
    out.push_str(&format!(
        "Declared Postgres: {}\n",
        bundle.versions.declared_postgres
    ));
    if let Some(ref s) = bundle.versions.observed_server {
        out.push_str(&format!("Observed Server:   {}\n", s));
    }
    if let Some(ref c) = bundle.versions.observed_client {
        out.push_str(&format!("Observed Client:   {}\n", c));
    }
    out.push('\n');

    out.push_str("--- STAGES ---\n");
    for s in &bundle.stages {
        let dur = s
            .duration_ms
            .map(|d| format!("{d} ms"))
            .unwrap_or_else(|| "-".to_owned());
        out.push_str(&format!("* {:<15} {:<12} {}\n", s.stage, s.status, dur));
    }
    out.push('\n');

    out.push_str("--- VERDICT ---\n");
    if let Some(ref v) = bundle.verdict {
        out.push_str(&format!("Verdict:          {}\n", v.verdict));
        if let Some(ref s) = v.stage {
            out.push_str(&format!("Stage:            {}\n", s));
        }
        if let Some(ref c) = v.code {
            out.push_str(&format!("Diagnostic Code:  {}\n", c));
        }
        if let Some(ref m) = v.message {
            out.push_str(&format!("Message:          {}\n", m));
        }
    } else {
        out.push_str("No terminal verdict recorded.\n");
    }
    out.push('\n');

    out.push_str("--- CLEANUP ---\n");
    if let Some(ref c) = bundle.cleanup {
        out.push_str(&format!("Cleanup Status:   {}\n", c.status));
        for err in &c.errors {
            out.push_str(&format!("* Error: {}\n", err));
        }
    } else {
        out.push_str("No cleanup record.\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;

    #[test]
    fn renders_deterministic_html_report() {
        let bundle = EvidenceBundle {
            schema_version: "v1".to_owned(),
            completeness: EvidenceCompleteness::Complete,
            run: RunEvidence {
                run_id: "test-run-123".to_owned(),
                owner: "drill-agent".to_owned(),
                created_at: "2026-09-08T12:00:00Z".to_owned(),
                completed_at: Some("2026-09-08T12:00:05Z".to_owned()),
                total_duration_ms: Some(5000),
            },
            tool: ToolEvidence {
                name: "salvage".to_owned(),
                version: "0.1.0".to_owned(),
            },
            manifest: ManifestEvidence {
                canonical_hash: "sha256:abc12345".to_owned(),
                declared: serde_json::json!({"test": "value"}),
            },
            backup: BackupEvidence {
                digest: "sha256:def67890".to_owned(),
                source: "local".to_owned(),
                restore_type: "full".to_owned(),
            },
            versions: VersionEvidence {
                declared_postgres: "16.4".to_owned(),
                observed_server: Some("PostgreSQL 16.4".to_owned()),
                observed_client: Some("pg_restore 16.4".to_owned()),
            },
            limits: LimitsEvidence {
                cpu_millicores: 500,
                memory_mib: 1024,
                disk_mib: 5120,
                restore_seconds: 60,
                verify_seconds: 30,
            },
            stages: vec![StageTimingEvidence {
                stage: "restore".to_owned(),
                status: "passed".to_owned(),
                duration_ms: Some(2500),
            }],
            verdict: Some(VerdictEvidence {
                verdict: "passed".to_owned(),
                stage: None,
                code: None,
                message: None,
                timeout_seconds: None,
                signal: None,
            }),
            verdict_classification: VerdictClassification::Verified,
            cleanup: Some(CleanupEvidence {
                status: "success".to_owned(),
                errors: Vec::new(),
            }),
            events: vec![],
            telemetry: TelemetryEvidence::default(),
        };

        let report1 = render_html_report(&bundle);
        let report2 = render_html_report(&bundle);
        assert_eq!(report1, report2);
        assert!(report1.contains("test-run-123"));
        assert!(report1.contains("VERIFIED"));
    }
}
