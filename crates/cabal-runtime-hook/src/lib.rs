//! Converts supported Codex `PostToolUse` payloads into model-safe projections.
//!
//! Raw tool output is never placed in the returned hook message. It is retained
//! only in local artifacts by the normalizer crates.

use std::path::{Path, PathBuf};

use cabal_delta::{DeltaPack, normalize_bytes as normalize_diff};
use cabal_observe::{InputKind, ObservationPack, normalize_bytes as normalize_observation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct PostToolUseInput {
    pub hook_event_name: String,
    pub cwd: PathBuf,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_response: Value,
}

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "continue")]
    pub should_continue: bool,
    #[serde(rename = "stopReason")]
    pub stop_reason: String,
}

/// Bounded model-facing fallback for malformed lifecycle payloads or local
/// runtime failures. It deliberately carries no implementation details.
pub fn fallback_output() -> HookOutput {
    HookOutput {
        should_continue: false,
        stop_reason: "{\"operation\":\"command\",\"result\":{\"status\":\"unknown\",\"completeness\":\"No structured semantic result is available for this operation.\"}}".to_owned(),
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "operation", content = "result", rename_all = "snake_case")]
enum ModelProjection {
    Build(BuildProjection),
    Diff(DiffProjection),
    Command(CommandProjection),
}

#[derive(Debug, Serialize)]
struct BuildProjection {
    status: String,
    diagnostics: Vec<ModelDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tests: Option<ModelTests>,
    completeness: String,
}

#[derive(Debug, Serialize)]
struct DiffProjection {
    status: String,
    files: Vec<ModelFileDelta>,
    summary: ModelDiffSummary,
    completeness: String,
}

#[derive(Debug, Serialize)]
struct CommandProjection {
    status: String,
    completeness: String,
}

#[derive(Debug, Serialize)]
struct ModelDiagnostic {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    related_locations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ModelTests {
    #[serde(skip_serializing_if = "Option::is_none")]
    passed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ignored: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ModelFileDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_path: Option<String>,
    change_kind: String,
    binary: bool,
    hunks: Vec<ModelHunk>,
    additions: u64,
    deletions: u64,
}

#[derive(Debug, Serialize)]
struct ModelHunk {
    old_start: u64,
    old_lines: u64,
    new_start: u64,
    new_lines: u64,
}

#[derive(Debug, Serialize)]
struct ModelDiffSummary {
    files_changed: u64,
    files_added: u64,
    files_deleted: u64,
    files_renamed: u64,
    binary_files: u64,
    additions: u64,
    deletions: u64,
}

#[derive(Debug)]
pub enum HookError {
    Json(serde_json::Error),
    Observation(cabal_observe::NormalizeError),
    Delta(cabal_delta::DeltaError),
    InvalidInput(&'static str),
}

impl std::fmt::Display for HookError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Observation(error) => write!(formatter, "observation error: {error}"),
            Self::Delta(error) => write!(formatter, "delta error: {error}"),
            Self::InvalidInput(message) => write!(formatter, "invalid hook input: {message}"),
        }
    }
}

impl std::error::Error for HookError {}

impl From<serde_json::Error> for HookError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<cabal_observe::NormalizeError> for HookError {
    fn from(error: cabal_observe::NormalizeError) -> Self {
        Self::Observation(error)
    }
}

impl From<cabal_delta::DeltaError> for HookError {
    fn from(error: cabal_delta::DeltaError) -> Self {
        Self::Delta(error)
    }
}

/// Returns `None` for non-Bash calls because current Codex hooks cannot cover
/// every tool path. Every intercepted Bash response is replaced by a bounded
/// projection so raw output never reaches the model through this hook path.
pub fn project_post_tool_use(input: PostToolUseInput) -> Result<Option<HookOutput>, HookError> {
    if input.hook_event_name != "PostToolUse" || input.tool_name != "Bash" {
        return Ok(None);
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(Value::as_str)
        .ok_or(HookError::InvalidInput("Bash command is missing"))?;
    let raw = response_bytes(&input.tool_response)?;
    let artifact_root = input.cwd.join(".cabal").join("artifacts");

    let projection = if is_git_diff(command) {
        normalize_diff(&raw, &artifact_root)
            .map(project_diff)
            .map(ModelProjection::Diff)
            .unwrap_or_else(|_| generic_projection("normalization_failed"))
    } else if let Some(kind) = build_input_kind(command, &raw) {
        normalize_observation(kind, &raw, &artifact_root)
            .map(project_observation)
            .map(ModelProjection::Build)
            .unwrap_or_else(|_| generic_projection("normalization_failed"))
    } else {
        generic_projection(command_status(&input.tool_response))
    };

    Ok(Some(HookOutput {
        should_continue: false,
        stop_reason: serde_json::to_string(&projection)?,
    }))
}

fn generic_projection(status: &str) -> ModelProjection {
    ModelProjection::Command(CommandProjection {
        status: status.to_owned(),
        completeness: "No structured semantic result is available for this operation.".to_owned(),
    })
}

fn command_status(response: &Value) -> &'static str {
    let exit_code = response
        .get("exit_code")
        .or_else(|| response.get("exitCode"))
        .and_then(Value::as_i64);
    match exit_code {
        Some(0) => "completed",
        Some(_) => "failed",
        None => "unknown",
    }
}

fn response_bytes(response: &Value) -> Result<Vec<u8>, HookError> {
    match response {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        Value::Object(object) => {
            for field in ["output", "stdout", "text"] {
                if let Some(Value::String(text)) = object.get(field) {
                    return Ok(text.as_bytes().to_vec());
                }
            }
            Ok(serde_json::to_vec(response)?)
        }
        _ => Ok(serde_json::to_vec(response)?),
    }
}

fn is_git_diff(command: &str) -> bool {
    command
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|parts| parts == ["git", "diff"])
}

fn build_input_kind(command: &str, raw: &[u8]) -> Option<InputKind> {
    let words = command.split_whitespace().collect::<Vec<_>>();
    if !words.windows(2).any(|parts| {
        parts == ["cargo", "build"]
            || parts == ["cargo", "check"]
            || parts == ["cargo", "clippy"]
            || parts == ["cargo", "test"]
    }) {
        return None;
    }

    if command.contains("--message-format=json") || looks_like_json_lines(raw) {
        Some(InputKind::CargoJson)
    } else {
        Some(InputKind::CargoTestText)
    }
}

fn looks_like_json_lines(raw: &[u8]) -> bool {
    raw.iter().copied().find(|byte| !byte.is_ascii_whitespace()) == Some(b'{')
}

fn project_observation(pack: ObservationPack) -> BuildProjection {
    BuildProjection {
        status: match pack.verdict {
            cabal_observe::Verdict::Passed => "passed",
            cabal_observe::Verdict::Failed => "failed",
            cabal_observe::Verdict::Unknown => "unknown",
        }
        .to_owned(),
        diagnostics: pack
            .diagnostics
            .into_iter()
            .map(|diagnostic| ModelDiagnostic {
                kind: diagnostic.kind,
                code: diagnostic.code,
                message: diagnostic.message,
                location: diagnostic.primary_location.as_ref().map(format_location),
                related_locations: diagnostic
                    .related_locations
                    .iter()
                    .map(format_location)
                    .collect(),
            })
            .collect(),
        tests: pack.tests.map(|tests| ModelTests {
            passed: tests.passed,
            failed: tests.failed,
            ignored: tests.ignored,
        }),
        completeness: pack.completeness,
    }
}

fn format_location(location: &cabal_observe::SourceLocation) -> String {
    format!("{}:{}:{}", location.file, location.line, location.column)
}

fn project_diff(pack: DeltaPack) -> DiffProjection {
    DiffProjection {
        status: match pack.verdict {
            cabal_delta::DeltaVerdict::Clean => "clean",
            cabal_delta::DeltaVerdict::Changed => "changed",
        }
        .to_owned(),
        files: pack
            .files
            .into_iter()
            .map(|file| ModelFileDelta {
                old_path: file.old_path,
                new_path: file.new_path,
                change_kind: match file.change_kind {
                    cabal_delta::ChangeKind::Added => "added",
                    cabal_delta::ChangeKind::Modified => "modified",
                    cabal_delta::ChangeKind::Deleted => "deleted",
                    cabal_delta::ChangeKind::Renamed => "renamed",
                }
                .to_owned(),
                binary: file.is_binary,
                hunks: file
                    .hunks
                    .into_iter()
                    .map(|hunk| ModelHunk {
                        old_start: hunk.old_start,
                        old_lines: hunk.old_lines,
                        new_start: hunk.new_start,
                        new_lines: hunk.new_lines,
                    })
                    .collect(),
                additions: file.additions,
                deletions: file.deletions,
            })
            .collect(),
        summary: ModelDiffSummary {
            files_changed: pack.summary.files_changed,
            files_added: pack.summary.files_added,
            files_deleted: pack.summary.files_deleted,
            files_renamed: pack.summary.files_renamed,
            binary_files: pack.summary.binary_files,
            additions: pack.summary.additions,
            deletions: pack.summary.deletions,
        },
        completeness: pack.completeness,
    }
}

pub fn artifact_root_for(cwd: &Path) -> PathBuf {
    cwd.join(".cabal").join("artifacts")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bash_input(command: &str, response: &str, cwd: &Path) -> PostToolUseInput {
        PostToolUseInput {
            hook_event_name: "PostToolUse".to_owned(),
            cwd: cwd.to_path_buf(),
            tool_name: "Bash".to_owned(),
            tool_input: serde_json::json!({ "command": command }),
            tool_response: Value::String(response.to_owned()),
        }
    }

    #[test]
    fn hides_raw_cargo_json_from_returned_hook_message() {
        let workspace = tempfile::tempdir().unwrap();
        let raw = "{\"reason\":\"compiler-message\",\"message\":{\"level\":\"error\",\"message\":\"use of moved value: `branches`\",\"code\":{\"code\":\"E0382\"},\"spans\":[{\"file_name\":\"src/query.rs\",\"line_start\":184,\"column_start\":9,\"is_primary\":true}]}}\n{\"reason\":\"build-finished\",\"success\":false}\n";

        let output = project_post_tool_use(bash_input(
            "cargo check --message-format=json",
            raw,
            workspace.path(),
        ))
        .unwrap()
        .unwrap();

        assert!(!output.should_continue);
        assert!(output.stop_reason.contains("E0382"));
        assert!(output.stop_reason.contains("src/query.rs:184:9"));
        assert!(!output.stop_reason.contains("artifact://"));
        assert!(!output.stop_reason.contains("sha256"));
        assert!(!output.stop_reason.contains("cabal"));
        assert!(artifact_root_for(workspace.path()).exists());
    }

    #[test]
    fn hides_raw_diff_but_retains_structural_delta() {
        let workspace = tempfile::tempdir().unwrap();
        let raw = "diff --git a/src/lib.rs b/src/lib.rs\nindex aaa..bbb 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

        let output = project_post_tool_use(bash_input("git diff", raw, workspace.path()))
            .unwrap()
            .unwrap();

        assert!(!output.should_continue);
        assert!(output.stop_reason.contains("\"operation\":\"diff\""));
        assert!(output.stop_reason.contains("src/lib.rs"));
        assert!(!output.stop_reason.contains("index aaa..bbb"));
        assert!(!output.stop_reason.contains("artifact://"));
    }

    #[test]
    fn hides_raw_output_for_unclassified_bash_commands() {
        let workspace = tempfile::tempdir().unwrap();

        let output =
            project_post_tool_use(bash_input("echo raw", "raw", workspace.path())).unwrap();

        let output = output.unwrap();
        assert!(!output.should_continue);
        assert!(output.stop_reason.contains("\"operation\":\"command\""));
        assert!(!output.stop_reason.contains("raw"));
        assert!(!output.stop_reason.contains("internally"));
    }

    #[test]
    fn fallback_projection_has_no_runtime_details() {
        let output = fallback_output();

        assert!(!output.should_continue);
        assert!(output.stop_reason.contains("\"operation\":\"command\""));
        for forbidden in ["cabal", "raw", "artifact://", "sha256", "internally"] {
            assert!(!output.stop_reason.contains(forbidden));
        }
    }
}
