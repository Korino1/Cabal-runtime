//! Deterministic normalization for compiler and test output.
//!
//! Raw output is stored outside model context. The resulting [`ObservationPack`]
//! preserves every structured compiler diagnostic or detected test failure.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "cabal.observation_pack.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    CargoJson,
    CargoTestText,
}

impl InputKind {
    pub fn parse(value: &str) -> Result<Self, NormalizeError> {
        match value {
            "cargo-json" => Ok(Self::CargoJson),
            "cargo-test-text" => Ok(Self::CargoTestText),
            _ => Err(NormalizeError::UnsupportedInputKind(value.to_owned())),
        }
    }

    fn operation(self) -> &'static str {
        match self {
            Self::CargoJson => "cargo-build",
            Self::CargoTestText => "cargo-test",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u64,
    pub column: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_location: Option<SourceLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<SourceLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignored: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedSections {
    pub count: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawArtifact {
    pub uri: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationPack {
    pub schema: String,
    pub operation: String,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<TestSummary>,
    pub omitted_sections: OmittedSections,
    pub completeness: String,
    pub raw_artifact: RawArtifact,
}

#[derive(Debug)]
struct ParsedObservation {
    verdict: Verdict,
    diagnostics: Vec<Diagnostic>,
    tests: Option<TestSummary>,
    omitted_count: u64,
    completeness: String,
}

#[derive(Debug)]
pub enum NormalizeError {
    Io(io::Error),
    Json(serde_json::Error),
    UnsupportedInputKind(String),
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::UnsupportedInputKind(kind) => write!(
                formatter,
                "unsupported input kind {kind:?}; expected cargo-json or cargo-test-text"
            ),
        }
    }
}

impl std::error::Error for NormalizeError {}

impl From<io::Error> for NormalizeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for NormalizeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn normalize_file(
    kind: InputKind,
    input: &Path,
    artifact_root: &Path,
) -> Result<ObservationPack, NormalizeError> {
    let raw = fs::read(input)?;
    normalize_bytes(kind, &raw, artifact_root)
}

pub fn normalize_bytes(
    kind: InputKind,
    raw: &[u8],
    artifact_root: &Path,
) -> Result<ObservationPack, NormalizeError> {
    let raw_artifact = persist_raw_artifact(raw, artifact_root)?;
    let text = String::from_utf8_lossy(raw);
    let parsed = match kind {
        InputKind::CargoJson => parse_cargo_json(&text)?,
        InputKind::CargoTestText => parse_cargo_test_text(&text),
    };

    Ok(ObservationPack {
        schema: SCHEMA_VERSION.to_owned(),
        operation: kind.operation().to_owned(),
        verdict: parsed.verdict,
        diagnostics: parsed.diagnostics,
        tests: parsed.tests,
        omitted_sections: OmittedSections {
            count: parsed.omitted_count,
            reason: "non-diagnostic build and test progress".to_owned(),
        },
        completeness: parsed.completeness,
        raw_artifact,
    })
}

fn persist_raw_artifact(raw: &[u8], artifact_root: &Path) -> Result<RawArtifact, io::Error> {
    let hash = format!("{:x}", Sha256::digest(raw));
    let directory = artifact_root.join(&hash);
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("raw-output"), raw)?;

    Ok(RawArtifact {
        uri: format!("artifact://observation/{hash}/raw-output"),
        sha256: hash,
        bytes: raw.len() as u64,
    })
}

fn parse_cargo_json(text: &str) -> Result<ParsedObservation, serde_json::Error> {
    let mut diagnostics = Vec::new();
    let mut saw_build_finished = None;
    let mut omitted_count = 0;

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line)?;
        match value.get("reason").and_then(serde_json::Value::as_str) {
            Some("compiler-message") => {
                if let Some(message) = value.get("message") {
                    if let Some(diagnostic) = compiler_message_to_diagnostic(message) {
                        diagnostics.push(diagnostic);
                    } else {
                        omitted_count += 1;
                    }
                } else {
                    omitted_count += 1;
                }
            }
            Some("build-finished") => {
                saw_build_finished = value.get("success").and_then(serde_json::Value::as_bool);
                omitted_count += 1;
            }
            Some(_) | None => omitted_count += 1,
        }
    }

    let verdict = if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "error")
    {
        Verdict::Failed
    } else if saw_build_finished == Some(true) {
        Verdict::Passed
    } else if saw_build_finished == Some(false) {
        Verdict::Failed
    } else {
        Verdict::Unknown
    };

    Ok(ParsedObservation {
        verdict,
        diagnostics,
        tests: None,
        omitted_count,
        completeness: "all structured compiler diagnostics retained".to_owned(),
    })
}

fn compiler_message_to_diagnostic(message: &serde_json::Value) -> Option<Diagnostic> {
    let level = message.get("level")?.as_str()?;
    let text = message.get("message")?.as_str()?.to_owned();
    let code = message
        .get("code")
        .and_then(|value| value.get("code"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    let mut locations = message
        .get("spans")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(span_to_location)
        .collect::<Vec<_>>();

    let primary_location = message
        .get("spans")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|span| span.get("is_primary").and_then(serde_json::Value::as_bool) == Some(true))
        .and_then(span_to_location)
        .or_else(|| locations.first().cloned());

    if let Some(primary) = &primary_location {
        locations.retain(|location| location != primary);
    }

    Some(Diagnostic {
        kind: level.to_owned(),
        code,
        message: text,
        primary_location,
        related_locations: locations,
    })
}

fn span_to_location(span: &serde_json::Value) -> Option<SourceLocation> {
    Some(SourceLocation {
        file: span.get("file_name")?.as_str()?.to_owned(),
        line: span.get("line_start")?.as_u64()?,
        column: span.get("column_start")?.as_u64()?,
    })
}

fn parse_cargo_test_text(text: &str) -> ParsedObservation {
    let mut diagnostics = Vec::new();
    let mut summary = None;
    let mut current_test = None;
    let mut pending_panic_location = None;
    let mut omitted_count = 0;

    for line in text.lines() {
        if let Some(test) = failed_test_line(line) {
            diagnostics.push(Diagnostic {
                kind: "test_failure".to_owned(),
                code: None,
                message: test,
                primary_location: None,
                related_locations: Vec::new(),
            });
            omitted_count += 1;
            continue;
        }

        if let Some(test) = failed_test_header(line) {
            current_test = Some(test);
            omitted_count += 1;
            continue;
        }

        if let Some((message, location)) = inline_panic_details(line) {
            record_test_panic(&mut diagnostics, current_test.as_deref(), message, location);
            continue;
        }

        if let Some(location) = panic_location(line) {
            pending_panic_location = Some(location);
            continue;
        }

        if let Some(location) = pending_panic_location.take() {
            if !line.trim().is_empty() {
                record_test_panic(
                    &mut diagnostics,
                    current_test.as_deref(),
                    line.trim().to_owned(),
                    Some(location),
                );
                continue;
            }
        }

        if let Some(parsed) = parse_test_summary(line) {
            summary = Some(match summary {
                Some(current) => merge_test_summaries(current, parsed),
                None => parsed,
            });
            continue;
        }

        if !line.trim().is_empty() {
            omitted_count += 1;
        }
    }

    let verdict = match &summary {
        Some(result) if result.failed.unwrap_or(0) > 0 => Verdict::Failed,
        Some(_) => Verdict::Passed,
        None if !diagnostics.is_empty() => Verdict::Failed,
        None => Verdict::Unknown,
    };

    ParsedObservation {
        verdict,
        diagnostics,
        tests: summary,
        omitted_count,
        completeness: "all detected test failures and parsed test summary retained".to_owned(),
    }
}

fn failed_test_header(line: &str) -> Option<String> {
    let value = line.trim();
    value
        .strip_prefix("---- ")?
        .strip_suffix(" stdout ----")
        .map(str::to_owned)
}

fn failed_test_line(line: &str) -> Option<String> {
    line.trim()
        .strip_prefix("test ")?
        .strip_suffix(" ... FAILED")
        .map(str::to_owned)
}

fn record_test_panic(
    diagnostics: &mut Vec<Diagnostic>,
    test: Option<&str>,
    message: String,
    location: Option<SourceLocation>,
) {
    if let Some(test) = test {
        if let Some(existing) = diagnostics
            .iter_mut()
            .find(|diagnostic| diagnostic.kind == "test_failure" && diagnostic.message == test)
        {
            existing.kind = "test_panic".to_owned();
            existing.message = format!("{test}: {message}");
            existing.primary_location = location;
            return;
        }

        diagnostics.push(Diagnostic {
            kind: "test_panic".to_owned(),
            code: None,
            message: format!("{test}: {message}"),
            primary_location: location,
            related_locations: Vec::new(),
        });
        return;
    }

    diagnostics.push(Diagnostic {
        kind: "test_panic".to_owned(),
        code: None,
        message,
        primary_location: location,
        related_locations: Vec::new(),
    });
}

fn inline_panic_details(line: &str) -> Option<(String, Option<SourceLocation>)> {
    let marker = "panicked at ";
    let index = line.find(marker)?;
    let details = line[index + marker.len()..].trim().trim_matches('\'');
    let (message, location_text) = details.rsplit_once(", ")?;
    Some((message.to_owned(), parse_location(location_text)))
}

fn panic_location(line: &str) -> Option<SourceLocation> {
    let marker = "panicked at ";
    let index = line.find(marker)?;
    let location = line[index + marker.len()..].trim().strip_suffix(':')?;
    parse_location(location)
}

fn parse_location(value: &str) -> Option<SourceLocation> {
    let (file, column) = value.rsplit_once(':')?;
    let (file, line) = file.rsplit_once(':')?;
    Some(SourceLocation {
        file: file.to_owned(),
        line: line.parse().ok()?,
        column: column.parse().ok()?,
    })
}

fn parse_test_summary(line: &str) -> Option<TestSummary> {
    let line = line.trim();
    if !line.starts_with("test result:") {
        return None;
    }

    Some(TestSummary {
        passed: summary_count(line, "passed"),
        failed: summary_count(line, "failed"),
        ignored: summary_count(line, "ignored"),
    })
}

fn merge_test_summaries(left: TestSummary, right: TestSummary) -> TestSummary {
    TestSummary {
        passed: merge_test_count(left.passed, right.passed),
        failed: merge_test_count(left.failed, right.failed),
        ignored: merge_test_count(left.ignored, right.ignored),
    }
}

fn merge_test_count(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left + right),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn summary_count(line: &str, name: &str) -> Option<u64> {
    let marker = format!(" {name};");
    let before = line.split_once(&marker)?.0;
    before.split_whitespace().last()?.parse().ok()
}

pub fn artifact_path(root: &Path, hash: &str) -> PathBuf {
    root.join(hash).join("raw-output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_structured_compiler_error_without_losing_locations() {
        let raw = br#"{"reason":"compiler-message","message":{"level":"error","message":"use of moved value: `branches`","code":{"code":"E0382"},"spans":[{"file_name":"src/query.rs","line_start":184,"column_start":9,"is_primary":true},{"file_name":"src/query.rs","line_start":171,"column_start":5,"is_primary":false}]}}
{"reason":"build-finished","success":false}
"#;
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(InputKind::CargoJson, raw, artifacts.path()).unwrap();

        assert_eq!(pack.verdict, Verdict::Failed);
        assert_eq!(pack.diagnostics.len(), 1);
        assert_eq!(pack.diagnostics[0].code.as_deref(), Some("E0382"));
        assert_eq!(
            pack.diagnostics[0].primary_location,
            Some(SourceLocation {
                file: "src/query.rs".to_owned(),
                line: 184,
                column: 9,
            })
        );
        assert_eq!(pack.diagnostics[0].related_locations.len(), 1);
        assert!(artifact_path(artifacts.path(), &pack.raw_artifact.sha256).is_file());
    }

    #[test]
    fn normalizes_successful_structured_build() {
        let raw = br#"{"reason":"compiler-artifact","package_id":"cabal 0.1.0"}
{"reason":"build-finished","success":true}
"#;
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(InputKind::CargoJson, raw, artifacts.path()).unwrap();

        assert_eq!(pack.verdict, Verdict::Passed);
        assert!(pack.diagnostics.is_empty());
        assert_eq!(pack.omitted_sections.count, 2);
    }

    #[test]
    fn normalizes_failed_test_with_panic_location() {
        let raw = b"running 2 tests\n\ntest parser::keeps_location ... ok\ntest parser::rejects_bad_log ... FAILED\n\n---- parser::rejects_bad_log stdout ----\n\nthread 'parser::rejects_bad_log' panicked at src/parser.rs:41:17:\nexpected structured output\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n\nfailures:\n    parser::rejects_bad_log\n\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(InputKind::CargoTestText, raw, artifacts.path()).unwrap();

        assert_eq!(pack.verdict, Verdict::Failed);
        assert_eq!(pack.tests.unwrap().failed, Some(1));
        assert_eq!(pack.diagnostics.len(), 1);
        assert_eq!(
            pack.diagnostics[0].primary_location,
            Some(SourceLocation {
                file: "src/parser.rs".to_owned(),
                line: 41,
                column: 17,
            })
        );
    }

    #[test]
    fn rejects_unknown_input_kind() {
        assert!(matches!(
            InputKind::parse("junit"),
            Err(NormalizeError::UnsupportedInputKind(_))
        ));
    }

    #[test]
    fn retains_a_failed_test_even_when_no_panic_text_is_present() {
        let raw = b"running 1 test\ntest parser::returns_error ... FAILED\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(InputKind::CargoTestText, raw, artifacts.path()).unwrap();

        assert_eq!(pack.verdict, Verdict::Failed);
        assert_eq!(pack.diagnostics.len(), 1);
        assert_eq!(pack.diagnostics[0].kind, "test_failure");
        assert_eq!(pack.diagnostics[0].message, "parser::returns_error");
    }

    #[test]
    fn aggregates_multiple_cargo_test_suite_summaries() {
        let raw = b"test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(InputKind::CargoTestText, raw, artifacts.path()).unwrap();

        assert_eq!(pack.verdict, Verdict::Passed);
        assert_eq!(pack.tests.unwrap().passed, Some(2));
    }
}
