use salvage_evidence::{
    BackupEvidence, CleanupEvidence, EvidenceBundle, EvidenceCompleteness, LimitsEvidence,
    ManifestEvidence, RunEvidence, SecretRedactor, StageTimingEvidence, ToolEvidence,
    VerdictClassification, VerdictEvidence, VersionEvidence, render_html_report,
};
use std::collections::BTreeMap;

#[test]
fn secret_canary_negative_test_fails_if_any_token_survives() {
    let canaries = vec![
        "CANARY_SECRET_DB_PASS_XYZ987",
        "CANARY_AWS_SECRET_KEY_456ABC",
        "CANARY_API_BEARER_TOKEN_789DEF",
        "CANARY_PRIVATE_KEY_TOKEN_321UVW",
        "CANARY_ENV_PASSWD_654MNO",
    ];

    let mut redactor = SecretRedactor::new();
    for canary in &canaries {
        redactor.add_secret(*canary);
    }

    // Set an env var to test add_env_secrets
    unsafe {
        std::env::set_var("SALVAGE_CANARY_SECRET", "CANARY_ENV_PASSWD_654MNO");
    }
    redactor.add_env_secrets();

    let mut bundle = EvidenceBundle {
        schema_version: "v1".to_owned(),
        completeness: EvidenceCompleteness::Complete,
        run: RunEvidence {
            run_id: "drill-canary-test".to_owned(),
            owner: format!("user-with-token-{}", canaries[2]),
            created_at: "2026-09-08T19:00:00Z".to_owned(),
            completed_at: Some("2026-09-08T19:00:10Z".to_owned()),
            total_duration_ms: Some(10000),
        },
        tool: ToolEvidence {
            name: "salvage".to_owned(),
            version: "0.1.0".to_owned(),
        },
        manifest: ManifestEvidence {
            canonical_hash: "sha256:1111222233334444555566667777888899990000".to_owned(),
            declared: serde_json::json!({
                "database_uri": format!("postgres://user:{}@localhost:5432/test", canaries[0]),
                "aws_key": "AKIAIOSFODNN7EXAMPLE",
                "custom_secret": canaries[1],
                "auth": {
                    "password": canaries[0],
                    "token": canaries[2],
                }
            }),
        },
        backup: BackupEvidence {
            digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_owned(),
            source: format!("s3://bucket?key={}", canaries[1]),
            restore_type: "full".to_owned(),
        },
        versions: VersionEvidence {
            declared_postgres: "16.4".to_owned(),
            observed_server: Some(format!(
                "PostgreSQL 16.4 (connected via password={})",
                canaries[0]
            )),
            observed_client: Some("pg_restore 16.4".to_owned()),
        },
        limits: LimitsEvidence {
            cpu_millicores: 500,
            memory_mib: 1024,
            disk_mib: 5120,
            restore_seconds: 60,
            verify_seconds: 30,
            boot_seconds: None,
        },
        artifact: None,
        stages: vec![StageTimingEvidence {
            stage: "restore".to_owned(),
            status: "failed".to_owned(),
            duration_ms: Some(500),
        }],
        verdict: Some(VerdictEvidence {
            verdict: "failed".to_owned(),
            stage: Some("restore".to_owned()),
            code: Some("restore/db-error".to_owned()),
            message: Some(format!(
                "failed to authenticate with password '{}' and bearer token '{}'",
                canaries[0], canaries[2]
            )),
            timeout_seconds: None,
            signal: None,
        }),
        verdict_classification: VerdictClassification::OrchestrationFailed,
        cleanup: Some(CleanupEvidence {
            status: "failed".to_owned(),
            errors: vec![format!("error cleaning up token: {}", canaries[4])],
        }),
        events: vec![
            serde_json::json!({
                "event": "command_run",
                "command": format!("pg_restore --password={} -U admin", canaries[0]),
            }),
            serde_json::json!({
                "event": "key_loaded",
                "key": format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----", canaries[3]),
            }),
        ],
        telemetry: salvage_evidence::TelemetryEvidence {
            target_dbname: Some("salvage_target".to_owned()),
            command_identity: Some(format!("pg_restore --token {}", canaries[2])),
            observed_app_version: None,
            observed_artifact_digest: None,
            verified_tables: vec!["users".to_owned()],
            custom: {
                let mut m = BTreeMap::new();
                m.insert("env_secret".to_owned(), canaries[4].to_string());
                m
            },
        },
    };

    // Redact bundle in place
    redactor.redact_bundle(&mut bundle);

    // Serialize to JSON and HTML report
    let json = bundle.to_canonical_json().expect("serialize bundle");
    let html = render_html_report(&bundle);
    let text = salvage_evidence::render_text_report(&bundle);

    // Assert that NONE of the canaries survived
    for canary in &canaries {
        assert!(
            !json.contains(canary),
            "CRITICAL SECURITY CANARY LEAK: canary token '{canary}' survived in JSON evidence!"
        );
        assert!(
            !html.contains(canary),
            "CRITICAL SECURITY CANARY LEAK: canary token '{canary}' survived in HTML report!"
        );
        assert!(
            !text.contains(canary),
            "CRITICAL SECURITY CANARY LEAK: canary token '{canary}' survived in text report!"
        );
    }

    // Assert that placeholder replaced them
    assert!(json.contains("[REDACTED]"));
    assert!(html.contains("[REDACTED]"));
}
