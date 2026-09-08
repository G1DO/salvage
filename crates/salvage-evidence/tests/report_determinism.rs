use salvage_evidence::{
    BackupEvidence, CleanupEvidence, EvidenceBundle, EvidenceCompleteness, LimitsEvidence,
    ManifestEvidence, RunEvidence, StageTimingEvidence, ToolEvidence, VerdictClassification,
    VerdictEvidence, VersionEvidence, render_html_report, render_text_report,
};

#[test]
fn report_projections_are_strictly_deterministic() {
    let bundle = EvidenceBundle {
        schema_version: "v1".to_owned(),
        completeness: EvidenceCompleteness::Complete,
        run: RunEvidence {
            run_id: "drill-determinism".to_owned(),
            owner: "operator".to_owned(),
            created_at: "2026-09-08T10:00:00Z".to_owned(),
            completed_at: Some("2026-09-08T10:00:15Z".to_owned()),
            total_duration_ms: Some(15000),
        },
        tool: ToolEvidence {
            name: "salvage".to_owned(),
            version: "0.1.0".to_owned(),
        },
        manifest: ManifestEvidence {
            canonical_hash:
                "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned(),
            declared: serde_json::json!({"limits": {"cpu_millicores": 500}}),
        },
        backup: BackupEvidence {
            digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
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
        stages: vec![
            StageTimingEvidence {
                stage: "planning".to_owned(),
                status: "passed".to_owned(),
                duration_ms: Some(10),
            },
            StageTimingEvidence {
                stage: "validation".to_owned(),
                status: "passed".to_owned(),
                duration_ms: Some(90),
            },
            StageTimingEvidence {
                stage: "restore".to_owned(),
                status: "passed".to_owned(),
                duration_ms: Some(1200),
            },
            StageTimingEvidence {
                stage: "verification".to_owned(),
                status: "passed".to_owned(),
                duration_ms: Some(45),
            },
            StageTimingEvidence {
                stage: "cleaning".to_owned(),
                status: "passed".to_owned(),
                duration_ms: Some(70),
            },
        ],
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
        events: vec![serde_json::json!({"step": 1, "action": "restore"})],
        telemetry: salvage_evidence::TelemetryEvidence {
            target_dbname: Some("salvage_restore".to_owned()),
            command_identity: Some("/usr/bin/pg_restore".to_owned()),
            verified_tables: vec!["users".to_owned(), "orders".to_owned()],
            custom: Default::default(),
        },
    };

    let html_1 = render_html_report(&bundle);
    let html_2 = render_html_report(&bundle);
    assert_eq!(
        html_1, html_2,
        "HTML report projection must be strictly deterministic"
    );

    let text_1 = render_text_report(&bundle);
    let text_2 = render_text_report(&bundle);
    assert_eq!(
        text_1, text_2,
        "Text report projection must be strictly deterministic"
    );
}
