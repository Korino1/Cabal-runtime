//! Deterministic, bounded normalization for test and tool output.

#![forbid(unsafe_code)]

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_DIAGNOSTICS: usize = 32;
pub const MAX_MESSAGE_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum InputKind {
    JunitXml,
    SarifJson,
    GenericText,
    NextestText,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Verdict {
    Passed,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticCategory {
    Failure,
    Error,
    Panic,
    Sarif,
    Log,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestCounts {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    pub category: DiagnosticCategory,
    pub rule_id: Option<String>,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
    pub suite: Option<String>,
    pub test: Option<String>,
    pub related_locations: Vec<SourceLocation>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceLocation {
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Omission {
    pub count: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawArtifactRecord {
    pub sha256: String,
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogPack {
    pub operation: String,
    pub kind: InputKind,
    pub verdict: Verdict,
    pub diagnostics: Vec<Diagnostic>,
    pub counts: TestCounts,
    pub omitted: Option<Omission>,
    pub complete: bool,
    #[serde(skip_serializing)]
    raw_artifact: RawArtifactRecord,
}

impl LogPack {
    pub fn raw_artifact(&self) -> &RawArtifactRecord {
        &self.raw_artifact
    }
}

#[derive(Debug)]
pub enum NormalizeError {
    Io(io::Error),
    JunitXml(String),
    SarifJson(String),
    InvalidSarif(String),
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "artifact I/O: {e}"),
            Self::JunitXml(e) => write!(f, "invalid JUnit XML: {e}"),
            Self::SarifJson(e) => write!(f, "invalid SARIF JSON: {e}"),
            Self::InvalidSarif(e) => write!(f, "invalid SARIF 2.1.0: {e}"),
        }
    }
}
impl std::error::Error for NormalizeError {}
impl From<io::Error> for NormalizeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Persists `raw` before parsing, then emits deterministic, bounded normalized data.
pub fn normalize_bytes(
    kind: InputKind,
    raw: &[u8],
    success: bool,
    artifact_root: impl AsRef<Path>,
) -> Result<LogPack, NormalizeError> {
    let artifact = persist_raw(raw, artifact_root.as_ref())?;
    let mut pack = match kind {
        InputKind::JunitXml => normalize_junit(raw)?,
        InputKind::SarifJson => normalize_sarif(raw)?,
        InputKind::GenericText => normalize_generic(raw),
        InputKind::NextestText => normalize_nextest(raw),
    };
    pack.kind = kind;
    pack.raw_artifact = artifact;
    // An observed non-zero process result is authoritative even where output is partial.
    if !success {
        pack.verdict = Verdict::Failed;
    }
    Ok(pack)
}

fn empty(kind: InputKind) -> LogPack {
    LogPack {
        operation: "normalize".into(),
        kind,
        verdict: Verdict::Unknown,
        diagnostics: Vec::new(),
        counts: TestCounts::default(),
        omitted: None,
        complete: true,
        raw_artifact: RawArtifactRecord {
            sha256: String::new(),
            path: PathBuf::new(),
            bytes: 0,
        },
    }
}

fn persist_raw(raw: &[u8], root: &Path) -> Result<RawArtifactRecord, NormalizeError> {
    let hash = format!("{:x}", Sha256::digest(raw));
    let dir = root.join("sha256");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{hash}.raw"));
    if !path.exists() {
        fs::write(&path, raw)?;
    }
    Ok(RawArtifactRecord {
        sha256: hash,
        path,
        bytes: raw.len() as u64,
    })
}

fn attr(e: &BytesStart<'_>, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}
fn number(e: &BytesStart<'_>, key: &[u8]) -> Option<u64> {
    attr(e, key)?.parse().ok()
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CaseOutcome {
    Passed,
    Skipped,
    Failure,
    Error,
}

fn normalize_junit(raw: &[u8]) -> Result<LogPack, NormalizeError> {
    let mut reader = Reader::from_reader(raw);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut pack = empty(InputKind::JunitXml);
    let mut suites = Vec::new();
    let mut current: Option<(Option<String>, Option<String>, CaseOutcome)> = None;
    let mut pending: Option<Diagnostic> = None;
    let mut open_elements = 0_u64;
    let mut saw_suite = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                open_elements += 1;
                match e.name().as_ref() {
                    b"testsuite" => {
                        saw_suite = true;
                        suites.push(attr(&e, b"name"));
                    }
                    b"testcase" => {
                        pack.counts.total += 1;
                        current = Some((
                            suites.last().cloned().flatten(),
                            attr(&e, b"name"),
                            CaseOutcome::Passed,
                        ));
                    }
                    b"failure" | b"error" => {
                        if let Some((suite, test, outcome)) = current.as_mut() {
                            let category = if e.name().as_ref() == b"error" {
                                *outcome = CaseOutcome::Error;
                                DiagnosticCategory::Error
                            } else {
                                if *outcome != CaseOutcome::Error {
                                    *outcome = CaseOutcome::Failure;
                                }
                                DiagnosticCategory::Failure
                            };
                            pending = Some(Diagnostic {
                                category,
                                rule_id: None,
                                message: attr(&e, b"message").unwrap_or_default(),
                                file: attr(&e, b"file"),
                                line: number(&e, b"line"),
                                column: number(&e, b"column"),
                                suite: suite.clone(),
                                test: test.clone(),
                                related_locations: Vec::new(),
                            });
                        }
                    }
                    b"skipped" => {
                        if let Some((_, _, outcome)) = current.as_mut() {
                            if *outcome == CaseOutcome::Passed {
                                *outcome = CaseOutcome::Skipped;
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"testsuite" => saw_suite = true,
                b"testcase" => {
                    pack.counts.total += 1;
                    pack.counts.passed += 1;
                }
                b"failure" | b"error" => {
                    if let Some((suite, test, outcome)) = current.as_mut() {
                        let category = if e.name().as_ref() == b"error" {
                            *outcome = CaseOutcome::Error;
                            DiagnosticCategory::Error
                        } else {
                            if *outcome != CaseOutcome::Error {
                                *outcome = CaseOutcome::Failure;
                            }
                            DiagnosticCategory::Failure
                        };
                        push_diag(
                            &mut pack,
                            Diagnostic {
                                category,
                                rule_id: None,
                                message: attr(&e, b"message").unwrap_or_default(),
                                file: attr(&e, b"file"),
                                line: number(&e, b"line"),
                                column: number(&e, b"column"),
                                suite: suite.clone(),
                                test: test.clone(),
                                related_locations: Vec::new(),
                            },
                        );
                    }
                }
                b"skipped" => {
                    if let Some((_, _, outcome)) = current.as_mut() {
                        if *outcome == CaseOutcome::Passed {
                            *outcome = CaseOutcome::Skipped;
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if let Some(d) = pending.as_mut() {
                    if d.message.is_empty() {
                        d.message = e
                            .unescape()
                            .map(|value| value.into_owned())
                            .unwrap_or_else(|_| String::from_utf8_lossy(e.as_ref()).into_owned());
                    }
                }
            }
            Ok(Event::End(e)) => {
                open_elements = open_elements
                    .checked_sub(1)
                    .ok_or_else(|| NormalizeError::JunitXml("unexpected closing element".into()))?;
                match e.name().as_ref() {
                    b"testsuite" => {
                        suites.pop();
                    }
                    b"failure" | b"error" => {
                        if let Some(d) = pending.take() {
                            push_diag(&mut pack, d);
                        }
                    }
                    b"testcase" => {
                        if let Some((_, _, outcome)) = current.take() {
                            match outcome {
                                CaseOutcome::Passed => pack.counts.passed += 1,
                                CaseOutcome::Skipped => pack.counts.skipped += 1,
                                CaseOutcome::Failure => pack.counts.failed += 1,
                                CaseOutcome::Error => pack.counts.errors += 1,
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => {
                if open_elements != 0 {
                    return Err(NormalizeError::JunitXml("unexpected end of file".into()));
                }
                break;
            }
            Err(e) => return Err(NormalizeError::JunitXml(e.to_string())),
            _ => {}
        };
        buf.clear();
    }
    if !saw_suite {
        return Err(NormalizeError::JunitXml(
            "expected a testsuite element".into(),
        ));
    }
    pack.verdict = if pack.counts.failed + pack.counts.errors > 0 {
        Verdict::Failed
    } else {
        Verdict::Passed
    };
    Ok(pack)
}

fn normalize_sarif(raw: &[u8]) -> Result<LogPack, NormalizeError> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|e| NormalizeError::SarifJson(e.to_string()))?;
    if value.get("version").and_then(Value::as_str) != Some("2.1.0") {
        return Err(NormalizeError::InvalidSarif("version must be 2.1.0".into()));
    }
    let runs = value
        .get("runs")
        .and_then(Value::as_array)
        .ok_or_else(|| NormalizeError::InvalidSarif("runs must be an array".into()))?;
    let mut pack = empty(InputKind::SarifJson);
    let mut results_seen = 0;
    for run in runs {
        for result in run
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            results_seen += 1;
            let level = result
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("warning");
            if level == "error" {
                pack.counts.failed += 1;
            }
            let primary = result
                .get("locations")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
                .map(source_location)
                .unwrap_or_default();
            let related_locations = result
                .get("relatedLocations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(source_location)
                .collect();
            let message = result
                .get("message")
                .and_then(|value| value.get("text").or_else(|| value.get("markdown")))
                .and_then(Value::as_str)
                .ok_or_else(|| NormalizeError::InvalidSarif("result message is required".into()))?;
            push_diag(
                &mut pack,
                Diagnostic {
                    category: DiagnosticCategory::Sarif,
                    rule_id: result
                        .get("ruleId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    message: message.into(),
                    file: primary.file,
                    line: primary.line,
                    column: primary.column,
                    suite: None,
                    test: None,
                    related_locations,
                },
            );
        }
    }
    pack.verdict = if pack.counts.failed > 0 {
        Verdict::Failed
    } else if results_seen > 0 {
        Verdict::Passed
    } else {
        Verdict::Unknown
    };
    if results_seen == 0 {
        pack.complete = false;
    }
    Ok(pack)
}

fn source_location(location: &Value) -> SourceLocation {
    let physical = location.get("physicalLocation");
    let region = physical.and_then(|v| v.get("region"));
    SourceLocation {
        file: physical
            .and_then(|v| v.get("artifactLocation"))
            .and_then(|v| v.get("uri"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        line: region
            .and_then(|v| v.get("startLine"))
            .and_then(Value::as_u64),
        column: region
            .and_then(|v| v.get("startColumn"))
            .and_then(Value::as_u64),
    }
}

fn normalize_generic(raw: &[u8]) -> LogPack {
    let mut pack = empty(InputKind::GenericText);
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("error") || lower.contains("fail") || lower.contains("panic") {
            let category = if lower.contains("panic") {
                DiagnosticCategory::Panic
            } else if lower.contains("error") {
                DiagnosticCategory::Error
            } else {
                DiagnosticCategory::Failure
            };
            let (file, line_no, column) = location_from(line);
            push_diag(
                &mut pack,
                Diagnostic {
                    category,
                    rule_id: None,
                    message: line.into(),
                    file,
                    line: line_no,
                    column,
                    suite: None,
                    test: None,
                    related_locations: Vec::new(),
                },
            );
        }
    }
    pack.verdict = if pack.diagnostics.is_empty() {
        Verdict::Unknown
    } else {
        Verdict::Failed
    };
    pack.complete = false;
    pack
}

fn normalize_nextest(raw: &[u8]) -> LogPack {
    let mut pack = empty(InputKind::NextestText);
    let text = String::from_utf8_lossy(raw);
    let mut observed = TestCounts::default();
    let mut summary: Option<TestCounts> = None;
    let mut bad_summary = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let token = trimmed.split_whitespace().next().unwrap_or("");
        let status = token.trim_end_matches(':');
        match status {
            "PASS" => {
                observed.total += 1;
                observed.passed += 1;
            }
            "FAIL" => {
                observed.total += 1;
                observed.failed += 1;
                let (file, line_number, column) = location_from(line);
                push_diag(
                    &mut pack,
                    Diagnostic {
                        category: DiagnosticCategory::Failure,
                        rule_id: None,
                        message: line.into(),
                        file,
                        line: line_number,
                        column,
                        suite: None,
                        test: test_after_duration(trimmed),
                        related_locations: Vec::new(),
                    },
                );
            }
            "SKIP" => {
                observed.total += 1;
                observed.skipped += 1;
            }
            _ => {}
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("summary") && lower.contains("test") {
            summary = parse_nextest_summary(&lower);
            if summary.is_none() {
                bad_summary = true;
            }
        }
        if lower.contains("panic") && status != "FAIL" {
            let (file, line_no, column) = location_from(line);
            push_diag(
                &mut pack,
                Diagnostic {
                    category: DiagnosticCategory::Panic,
                    rule_id: None,
                    message: line.into(),
                    file,
                    line: line_no,
                    column,
                    suite: None,
                    test: None,
                    related_locations: Vec::new(),
                },
            );
        }
    }
    match summary {
        Some(s) if !bad_summary && (observed.total == 0 || observed == s) => {
            pack.counts = s;
            pack.complete = true;
            pack.verdict = if s.failed + s.errors > 0 {
                Verdict::Failed
            } else {
                Verdict::Passed
            };
        }
        _ => {
            pack.counts = observed;
            pack.complete = false;
            pack.verdict = if observed.failed > 0 {
                Verdict::Failed
            } else {
                Verdict::Unknown
            };
        }
    }
    if bad_summary || (summary.is_some() && summary != Some(observed) && observed.total > 0) {
        pack.verdict = Verdict::Unknown;
        pack.complete = false;
    }
    pack
}

fn parse_nextest_summary(line: &str) -> Option<TestCounts> {
    let mut counts = TestCounts::default();
    let mut found = false;
    let words: Vec<_> = line
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    for pair in words.windows(2) {
        if let Ok(n) = pair[0].parse() {
            match pair[1] {
                "passed" => {
                    counts.passed = n;
                    found = true;
                }
                "failed" => {
                    counts.failed = n;
                    found = true;
                }
                "skipped" => {
                    counts.skipped = n;
                    found = true;
                }
                "error" | "errors" => {
                    counts.errors = n;
                    found = true;
                }
                _ => {}
            }
        }
    }
    counts.total = counts.passed + counts.failed + counts.skipped + counts.errors;
    found.then_some(counts)
}

fn test_after_duration(line: &str) -> Option<String> {
    line.rsplit(']')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
fn location_from(line: &str) -> (Option<String>, Option<u64>, Option<u64>) {
    let candidate = line
        .rsplit_once(" at ")
        .map_or(line, |(_, location)| location);
    let parts: Vec<_> = candidate.trim_end_matches(':').split(':').collect();
    if parts.len() < 3 {
        return (None, None, None);
    }
    let column = parts[parts.len() - 1].trim().parse().ok();
    let line_no = parts[parts.len() - 2].trim().parse().ok();
    if line_no.is_some() {
        (Some(parts[..parts.len() - 2].join(":")), line_no, column)
    } else {
        (None, None, None)
    }
}
fn push_diag(pack: &mut LogPack, mut d: Diagnostic) {
    d.message = truncate(&d.message, MAX_MESSAGE_CHARS);
    if pack.diagnostics.len() < MAX_DIAGNOSTICS {
        pack.diagnostics.push(d);
    } else {
        let o = pack.omitted.get_or_insert(Omission {
            count: 0,
            reason: "diagnostic limit exceeded".into(),
        });
        o.count += 1;
    }
}
fn truncate(value: &str, max: usize) -> String {
    let mut out = value.chars().take(max).collect::<String>();
    if value.chars().count() > max {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests;
