use super::*;
use std::fs;
use tempfile::tempdir;

fn fixture(name: &str) -> Vec<u8> {
    fs::read(format!("tests/fixtures/{name}")).unwrap()
}
fn normalized(kind: InputKind, name: &str, success: bool) -> LogPack {
    let dir = tempdir().unwrap();
    normalize_bytes(kind, &fixture(name), success, dir.path()).unwrap()
}

#[test]
fn junit_aggregates_suites_and_locations() {
    let p = normalized(InputKind::JunitXml, "multi-suite.xml", true);
    assert_eq!(p.verdict, Verdict::Failed);
    assert_eq!(
        p.counts,
        TestCounts {
            total: 4,
            passed: 1,
            failed: 1,
            skipped: 1,
            errors: 1
        }
    );
    assert_eq!(p.diagnostics[0].file.as_deref(), Some("src/lib.rs"));
    assert_eq!(p.diagnostics[0].suite.as_deref(), Some("integration"));
}
#[test]
fn junit_malformed_is_an_error() {
    let dir = tempdir().unwrap();
    assert!(matches!(
        normalize_bytes(InputKind::JunitXml, b"<testsuite>", true, dir.path()),
        Err(NormalizeError::JunitXml(_))
    ));
    assert!(matches!(
        normalize_bytes(InputKind::JunitXml, b"<not-junit/>", true, dir.path()),
        Err(NormalizeError::JunitXml(_))
    ));
}

#[test]
fn junit_decodes_attribute_entities() {
    let dir = tempdir().unwrap();
    let raw = br#"<testsuite name="a &amp; b"><testcase name="x"><failure message="left &lt; right"/></testcase></testsuite>"#;
    let p = normalize_bytes(InputKind::JunitXml, raw, true, dir.path()).unwrap();
    assert_eq!(p.diagnostics[0].suite.as_deref(), Some("a & b"));
    assert_eq!(p.diagnostics[0].message, "left < right");
}
#[test]
fn sarif_reads_primary_and_related_locations() {
    let p = normalized(InputKind::SarifJson, "sarif-locations.json", true);
    assert_eq!(p.verdict, Verdict::Failed);
    assert_eq!(p.diagnostics.len(), 2);
    assert_eq!(p.diagnostics[0].file.as_deref(), Some("src/main.rs"));
    assert_eq!(p.diagnostics[0].line, Some(8));
    assert_eq!(p.diagnostics[0].related_locations.len(), 1);
    assert_eq!(
        p.diagnostics[0].related_locations[0].file.as_deref(),
        Some("src/lib.rs")
    );
}
#[test]
fn sarif_invalid_json_and_version_fail() {
    let dir = tempdir().unwrap();
    assert!(matches!(
        normalize_bytes(InputKind::SarifJson, b"{", true, dir.path()),
        Err(NormalizeError::SarifJson(_))
    ));
    assert!(matches!(
        normalize_bytes(
            InputKind::SarifJson,
            br#"{"version":"2.0.0"}"#,
            true,
            dir.path()
        ),
        Err(NormalizeError::InvalidSarif(_))
    ));
    assert!(matches!(
        normalize_bytes(
            InputKind::SarifJson,
            br#"{"version":"2.1.0"}"#,
            true,
            dir.path()
        ),
        Err(NormalizeError::InvalidSarif(_))
    ));
    assert!(matches!(
        normalize_bytes(
            InputKind::SarifJson,
            br#"{"version":"2.1.0","runs":[{"results":[{"level":"warning"}]}]}"#,
            true,
            dir.path()
        ),
        Err(NormalizeError::InvalidSarif(_))
    ));
}
#[test]
fn generic_is_bounded_and_tracks_omission() {
    let raw = (0..40)
        .map(|_| format!("ERROR {}\n", "x".repeat(600)))
        .collect::<String>();
    let dir = tempdir().unwrap();
    let p = normalize_bytes(InputKind::GenericText, raw.as_bytes(), true, dir.path()).unwrap();
    assert_eq!(p.diagnostics.len(), 32);
    assert_eq!(p.omitted.as_ref().unwrap().count, 8);
    assert!(p.diagnostics[0].message.chars().count() <= 515);
}

#[test]
fn generic_extracts_actionable_location_without_log_prefix() {
    let dir = tempdir().unwrap();
    let p = normalize_bytes(
        InputKind::GenericText,
        b"ERROR compilation failed at src/main.rs:44:2\n",
        false,
        dir.path(),
    )
    .unwrap();
    assert_eq!(p.diagnostics[0].file.as_deref(), Some("src/main.rs"));
    assert_eq!(p.diagnostics[0].line, Some(44));
    assert_eq!(p.diagnostics[0].column, Some(2));
}
#[test]
fn nextest_preserves_pass_fail_skip_and_location() {
    let p = normalized(InputKind::NextestText, "nextest-failing.txt", true);
    assert_eq!(p.verdict, Verdict::Failed);
    assert_eq!(p.counts.failed, 1);
    assert!(p.diagnostics.iter().any(|d| {
        d.category == DiagnosticCategory::Panic
            && d.file.as_deref() == Some("src/lib.rs")
            && d.line == Some(12)
    }));
    let p = normalized(InputKind::NextestText, "nextest-passing.txt", true);
    assert_eq!(p.verdict, Verdict::Passed);
    assert_eq!(p.counts.skipped, 1);
}
#[test]
fn nextest_contradictions_are_unknown_but_exit_failure_wins() {
    let dir = tempdir().unwrap();
    let raw = b"PASS [0.1s] a\nSummary 1 tests run: 0 passed, 1 failed, 0 skipped\n";
    let p = normalize_bytes(InputKind::NextestText, raw, true, dir.path()).unwrap();
    assert_eq!(p.verdict, Verdict::Unknown);
    assert!(!p.complete);
    let p = normalize_bytes(InputKind::NextestText, raw, false, dir.path()).unwrap();
    assert_eq!(p.verdict, Verdict::Failed);
}
#[test]
fn raw_bytes_are_content_addressed_and_persisted() {
    let dir = tempdir().unwrap();
    let p = normalize_bytes(InputKind::GenericText, b"hello", true, dir.path()).unwrap();
    assert_eq!(fs::read(p.raw_artifact().path.clone()).unwrap(), b"hello");
    assert_eq!(p.raw_artifact().sha256.len(), 64);
}
