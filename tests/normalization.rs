use std::path::Path;

use cabal_observe::{InputKind, Verdict, normalize_file};

fn normalize_fixture(name: &str, kind: InputKind) -> cabal_observe::ObservationPack {
    let artifacts = tempfile::tempdir().unwrap();
    let fixture = Path::new("tests/fixtures").join(name);
    normalize_file(kind, &fixture, artifacts.path()).unwrap()
}

#[test]
fn structured_error_fixture_preserves_all_actionable_fields() {
    let pack = normalize_fixture("cargo-error.jsonl", InputKind::CargoJson);
    let diagnostic = pack.diagnostics.first().unwrap();

    assert_eq!(pack.verdict, Verdict::Failed);
    assert_eq!(diagnostic.kind, "error");
    assert_eq!(diagnostic.code.as_deref(), Some("E0382"));
    assert_eq!(diagnostic.message, "use of moved value: `branches`");
    assert_eq!(
        diagnostic.primary_location.as_ref().unwrap().file,
        "src/query.rs"
    );
    assert_eq!(diagnostic.primary_location.as_ref().unwrap().line, 184);
    assert_eq!(diagnostic.related_locations.len(), 1);
}

#[test]
fn successful_build_fixture_is_not_reported_as_a_failure() {
    let pack = normalize_fixture("cargo-success.jsonl", InputKind::CargoJson);

    assert_eq!(pack.verdict, Verdict::Passed);
    assert!(pack.diagnostics.is_empty());
}

#[test]
fn test_failure_fixture_retains_failure_count_and_location() {
    let pack = normalize_fixture("cargo-test-failure.txt", InputKind::CargoTestText);
    let diagnostic = pack.diagnostics.first().unwrap();

    assert_eq!(pack.verdict, Verdict::Failed);
    assert_eq!(pack.tests.as_ref().unwrap().failed, Some(1));
    assert_eq!(diagnostic.kind, "test_panic");
    assert_eq!(
        diagnostic.primary_location.as_ref().unwrap().file,
        "src/parser.rs"
    );
    assert_eq!(diagnostic.primary_location.as_ref().unwrap().line, 41);
}

#[test]
fn noisy_build_fixture_has_a_smaller_model_projection() {
    let raw = include_bytes!("fixtures/cargo-noisy-build.jsonl");
    let artifacts = tempfile::tempdir().unwrap();
    let pack = cabal_observe::normalize_bytes(InputKind::CargoJson, raw, artifacts.path()).unwrap();
    let projection = serde_json::to_vec(&pack).unwrap();

    assert_eq!(pack.verdict, Verdict::Failed);
    assert_eq!(pack.diagnostics.len(), 1);
    assert_eq!(pack.diagnostics[0].code.as_deref(), Some("E0596"));
    assert!(projection.len() < raw.len());
}
