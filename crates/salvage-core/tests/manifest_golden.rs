use std::path::Path;

use salvage_core::manifest::{manifest_hash, parse_manifest};

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn expected_diagnostics() -> serde_json::Value {
    let text = std::fs::read_to_string(fixture_path("manifest-diagnostics.json"))
        .expect("diagnostics map must exist");
    serde_json::from_str(&text).expect("diagnostics map must be valid JSON")
}

#[test]
fn golden_fixtures_map_to_stable_diagnostic_codes() {
    let expected = expected_diagnostics();
    let map = expected.as_object().expect("diagnostics map is an object");
    let mut files: Vec<&String> = map.keys().collect();
    files.sort();

    for file in files {
        let want = map[file].as_str().expect("diagnostic code is a string");
        let text = std::fs::read_to_string(fixture_path(file))
            .unwrap_or_else(|_| panic!("fixture {file} must exist"));
        if want == "ok" {
            let manifest = parse_manifest(&text)
                .unwrap_or_else(|error| panic!("fixture {file} must parse: {error}"));
            let hash = manifest_hash(&manifest);
            assert!(
                hash.starts_with("sha256:") && hash.len() == 7 + 64,
                "fixture {file} must produce a sha256 hash"
            );
        } else {
            let error = parse_manifest(&text).expect_err(&format!("fixture {file} must fail"));
            assert_eq!(error.code(), want, "fixture {file}");
        }
    }
}

#[test]
fn valid_fixture_hash_is_stable() {
    let text = std::fs::read_to_string(fixture_path("manifest-valid-v1.json")).expect("valid");
    let first = parse_manifest(&text).expect("valid");
    let second = parse_manifest(&text).expect("valid");
    assert_eq!(manifest_hash(&first), manifest_hash(&second));
    assert_eq!(
        manifest_hash(&first),
        "sha256:2c3387d729c27ff8782734b7abf27463d7b4a8808ec5574b5801c321dd772fa3",
        "canonical hash of the valid fixture must not drift",
    );
}
