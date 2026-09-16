use salvage_evidence::{
    BackupEvidence, CleanupEvidence, ContractEvidence, EgressEvidence, EvidenceBundle,
    EvidenceCompleteness, IsolationEvidence, LimitsEvidence, ManifestEvidence, RunEvidence,
    SecretRedactor, StageTimingEvidence, ToolEvidence, VerdictClassification, VerdictEvidence,
    VersionEvidence, parse_evidence_bundle, render_html_report, render_text_report,
};

fn base_bundle() -> EvidenceBundle {
    EvidenceBundle {
        schema_version: "v1".to_owned(),
        completeness: EvidenceCompleteness::Complete,
        run: RunEvidence {
            run_id: "drill-o3-4".to_owned(),
            owner: "operator".to_owned(),
            created_at: "2026-09-16T00:00:00Z".to_owned(),
            completed_at: Some("2026-09-16T00:00:10Z".to_owned()),
            total_duration_ms: Some(10000),
        },
        tool: ToolEvidence {
            name: "salvage".to_owned(),
            version: "0.1.0".to_owned(),
        },
        manifest: ManifestEvidence {
            canonical_hash: "sha256:1111222233334444555566667777888899990000".to_owned(),
            declared: serde_json::json!({"schema_version": "v3"}),
        },
        backup: BackupEvidence {
            digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
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
            boot_seconds: Some(120),
        },
        artifact: None,
        stages: vec![StageTimingEvidence {
            stage: "contracts".to_owned(),
            status: "passed".to_owned(),
            duration_ms: Some(12),
        }],
        contracts: None,
        isolation: None,
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
        telemetry: salvage_evidence::TelemetryEvidence::default(),
    }
}

#[test]
fn contract_canary_never_survives_json_or_reports() {
    // Attacker-influenced outputs: SQL rows, HTTP body, exec stderr.
    let canaries = [
        "CANARY_SQL_OUTPUT_XYZ987",
        "CANARY_HTTP_BODY_456ABC",
        "CANARY_EXEC_STDERR_789DEF",
    ];
    let mut redactor = SecretRedactor::new();
    for c in &canaries {
        redactor.add_secret(*c);
    }

    let mut bundle = base_bundle();
    bundle.contracts = Some(vec![
        ContractEvidence {
            name: "sql-probe".to_owned(),
            kind: "sql".to_owned(),
            status: "passed".to_owned(),
            code: None,
            output: format!("row1\nsecret leak {}", canaries[0]),
            truncated: false,
            duration_ms: Some(5),
            rows: 2,
        },
        ContractEvidence {
            name: "http-probe".to_owned(),
            kind: "http".to_owned(),
            status: "failed".to_owned(),
            code: Some("contract/assert-failed".to_owned()),
            output: format!("body contains {}", canaries[1]),
            truncated: false,
            duration_ms: Some(7),
            rows: 0,
        },
        ContractEvidence {
            name: "exec-probe".to_owned(),
            kind: "exec".to_owned(),
            status: "failed".to_owned(),
            code: Some("contract/crash".to_owned()),
            output: format!("stderr: {}", canaries[2]),
            truncated: false,
            duration_ms: Some(3),
            rows: 0,
        },
    ]);
    bundle.isolation = Some(IsolationEvidence {
        network: Some("salvage-net-drill".to_owned()),
        allowlist: vec![],
        egress: EgressEvidence {
            host: "prod-forbidden.invalid".to_owned(),
            allowed: false,
            detail: format!("blocked, saw {}", canaries[1]),
        },
    });
    // Classification must not be Verified when contracts failed; use
    // VerificationFailed so validate() passes and we test redaction only.
    bundle.verdict_classification = VerdictClassification::VerificationFailed;

    redactor.redact_bundle(&mut bundle);

    let json = bundle.to_canonical_json().expect("serialize");
    let html = render_html_report(&bundle);
    let text = render_text_report(&bundle);
    for canary in &canaries {
        assert!(
            !json.contains(canary),
            "canary {canary} survived in evidence.json"
        );
        assert!(
            !html.contains(canary),
            "canary {canary} survived in report.html"
        );
        assert!(
            !text.contains(canary),
            "canary {canary} survived in text report"
        );
    }
    assert!(json.contains("[REDACTED]"));
    assert!(html.contains("[REDACTED]"));
}

#[test]
fn verified_with_failed_contracts_is_rejected_as_incomplete() {
    let mut bundle = base_bundle();
    bundle.contracts = Some(vec![ContractEvidence {
        name: "health".to_owned(),
        kind: "http".to_owned(),
        status: "failed".to_owned(),
        code: Some("contract/assert-failed".to_owned()),
        output: "non-2xx".to_owned(),
        truncated: false,
        duration_ms: Some(4),
        rows: 0,
    }]);
    bundle.verdict_classification = VerdictClassification::Verified;
    let err = bundle
        .validate()
        .expect_err("failed contracts can never verify");
    assert!(matches!(
        err,
        salvage_evidence::EvidenceError::Incomplete { .. }
    ));
}

#[test]
fn verified_with_empty_contracts_is_rejected() {
    let mut bundle = base_bundle();
    bundle.contracts = Some(vec![]);
    bundle.verdict_classification = VerdictClassification::Verified;
    assert!(bundle.validate().is_err());
}

#[test]
fn verified_with_passing_contracts_and_legacy_none_both_validate() {
    // v3: non-empty all-passed verifies.
    let mut v3 = base_bundle();
    v3.contracts = Some(vec![ContractEvidence {
        name: "ok".to_owned(),
        kind: "sql".to_owned(),
        status: "passed".to_owned(),
        code: None,
        output: "1".to_owned(),
        truncated: false,
        duration_ms: Some(2),
        rows: 1,
    }]);
    v3.verdict_classification = VerdictClassification::Verified;
    v3.validate().expect("v3 all-passed verifies");

    // Legacy v1/v2: None preserves old Verified semantics.
    let mut legacy = base_bundle();
    legacy.contracts = None;
    legacy.verdict_classification = VerdictClassification::Verified;
    legacy.validate().expect("legacy None verifies");
    let json = legacy.to_canonical_json().expect("ser");
    assert!(!json.contains("\"contracts\":"));
    assert!(!json.contains("\"isolation\":"));
    let again = parse_evidence_bundle(&json).expect("reparse legacy");
    assert_eq!(again.contracts, None);
    assert_eq!(again.isolation, None);
}

#[test]
fn contracts_and_isolation_reports_are_deterministic() {
    let mut bundle = base_bundle();
    bundle.contracts = Some(vec![ContractEvidence {
        name: "ok".to_owned(),
        kind: "exec".to_owned(),
        status: "passed".to_owned(),
        code: None,
        output: "hello".to_owned(),
        truncated: false,
        duration_ms: Some(9),
        rows: 0,
    }]);
    bundle.isolation = Some(IsolationEvidence {
        network: Some("salvage-net-drill".to_owned()),
        allowlist: vec!["api.example.com".to_owned()],
        egress: EgressEvidence {
            host: "prod-forbidden.invalid".to_owned(),
            allowed: false,
            detail: "wget blocked".to_owned(),
        },
    });
    let h1 = render_html_report(&bundle);
    let h2 = render_html_report(&bundle);
    assert_eq!(h1, h2);
    assert!(h1.contains("Recovery Contracts"));
    assert!(h1.contains("Boot Isolation"));
    assert!(h1.contains("api.example.com"));
    let t1 = render_text_report(&bundle);
    let t2 = render_text_report(&bundle);
    assert_eq!(t1, t2);
    assert!(t1.contains("--- CONTRACTS ---"));
    assert!(t1.contains("--- ISOLATION ---"));
}
