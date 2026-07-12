//! Rewrites supported Codex `PreToolUse` operations to native model-safe gateways.
//!
//! Raw tool output is never placed in the returned hook message. It is retained
//! only in local artifacts by the normalizer crates.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use cabal_change_policy::{
    Decision as ChangeDecision, PolicyState as ChangePolicyState, ToolInput as ChangeToolInput,
    evaluate as evaluate_change, receipt_for as change_receipt_for,
    write_receipt as write_change_receipt,
};
use cabal_completion_gate::{
    CargoCommand as CompletionCargoCommand, CargoOutcome, GateError, GateStatus,
    evaluate as evaluate_completion, record_cargo_outcome,
};
use cabal_delta::{
    DeltaPack, GitStatusPack, StatusKind, normalize_bytes as normalize_diff, normalize_status_bytes,
};
use cabal_file_cache::{
    FileObservation, RequestedRange, invalidate_observations, observe_file, supports_request,
};
use cabal_log::{
    InputKind as LogInputKind, LogPack, Verdict as LogVerdict, normalize_bytes as normalize_log,
};
use cabal_observe::{InputKind, ObservationPack, normalize_bytes as normalize_observation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
pub struct PostToolUseInput {
    pub hook_event_name: String,
    pub cwd: PathBuf,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_response: Value,
}

/// Input emitted by Codex before a supported tool call.
#[derive(Debug, Deserialize)]
pub struct PreToolUseInput {
    pub hook_event_name: String,
    pub cwd: PathBuf,
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StopInput {
    pub hook_event_name: String,
    pub cwd: PathBuf,
    pub stop_hook_active: bool,
}

#[derive(Debug, Serialize)]
pub struct StopOutput {
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    should_continue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl StopOutput {
    fn pass() -> Self {
        Self {
            should_continue: Some(true),
            decision: None,
            reason: None,
        }
    }

    fn block(reason: String) -> Self {
        Self {
            should_continue: None,
            decision: Some("block"),
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PreToolUseOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: PreToolUseSpecificOutput,
}

#[derive(Debug, Serialize)]
struct PreToolUseSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    permission_decision_reason: Option<String>,
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    updated_input: Option<UpdatedToolInput>,
}

#[derive(Debug, Serialize)]
struct UpdatedToolInput {
    command: String,
}

impl PreToolUseOutput {
    fn rewrite(command: String) -> Self {
        Self {
            hook_specific_output: PreToolUseSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "allow",
                permission_decision_reason: None,
                updated_input: Some(UpdatedToolInput { command }),
            },
        }
    }

    fn deny(code: &str) -> Self {
        Self {
            hook_specific_output: PreToolUseSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: Some(format!(
                    "Change blocked by policy: {}.",
                    safe_policy_code(code)
                )),
                updated_input: None,
            },
        }
    }
}

fn safe_policy_code(code: &str) -> &str {
    if !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        code
    } else {
        "policy_denied"
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CargoExecutionRequest {
    cwd: PathBuf,
    cargo_args: Vec<String>,
    receipt_args: Vec<String>,
    kind: CargoExecutionKind,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CargoExecutionKind {
    BuildJson,
    TestText,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct LogExecutionRequest {
    cwd: PathBuf,
    source: LogExecutionSource,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "snake_case")]
enum LogExecutionSource {
    File { path: PathBuf, kind: LogInputKind },
    Nextest { cargo_args: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct GitExecutionRequest {
    cwd: PathBuf,
    query: GitQuery,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "query", rename_all = "snake_case")]
enum GitQuery {
    Status,
    Diff,
    DiffCached,
    Show { revision: String },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct FileReadExecutionRequest {
    cwd: PathBuf,
    path: PathBuf,
    session_id: String,
    requested: RequestedRange,
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
    Test(BuildProjection),
    Diff(DiffProjection),
    Log(LogProjection),
    Git(GitProjection),
    FileRead(FileObservation),
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
struct GitProjection {
    query: String,
    status: String,
    files: Vec<ModelGitFile>,
    summary: ModelGitSummary,
    omitted_files: u64,
    omitted_hunks: u64,
    completeness: String,
}

#[derive(Debug, Serialize)]
struct ModelGitFile {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_kind: Option<String>,
    classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    index_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktree_status: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    untracked: bool,
    #[serde(skip_serializing_if = "is_false")]
    binary: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hunks: Vec<ModelHunk>,
    #[serde(skip_serializing_if = "is_zero")]
    additions: u64,
    #[serde(skip_serializing_if = "is_zero")]
    deletions: u64,
}

#[derive(Debug, Default, Serialize)]
struct ModelGitSummary {
    files_changed: u64,
    #[serde(skip_serializing_if = "is_zero")]
    files_added: u64,
    #[serde(skip_serializing_if = "is_zero")]
    files_deleted: u64,
    #[serde(skip_serializing_if = "is_zero")]
    files_renamed: u64,
    #[serde(skip_serializing_if = "is_zero")]
    binary_files: u64,
    #[serde(skip_serializing_if = "is_zero")]
    additions: u64,
    #[serde(skip_serializing_if = "is_zero")]
    deletions: u64,
    #[serde(skip_serializing_if = "is_zero")]
    staged: u64,
    #[serde(skip_serializing_if = "is_zero")]
    unstaged: u64,
    #[serde(skip_serializing_if = "is_zero")]
    untracked: u64,
    #[serde(skip_serializing_if = "is_zero")]
    conflicts: u64,
}

#[derive(Debug, Serialize)]
struct CommandProjection {
    status: String,
    completeness: String,
}

#[derive(Debug, Serialize)]
struct LogProjection {
    format: String,
    status: String,
    diagnostics: Vec<ModelDiagnostic>,
    counts: ModelLogCounts,
    omitted: u64,
    completeness: String,
}

#[derive(Debug, Serialize)]
struct ModelLogCounts {
    total: u64,
    passed: u64,
    failed: u64,
    skipped: u64,
    errors: u64,
}

#[derive(Debug, Serialize)]
struct ModelDiagnostic {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    test: Option<String>,
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
    Io(std::io::Error),
    Json(serde_json::Error),
    Observation(cabal_observe::NormalizeError),
    Delta(cabal_delta::DeltaError),
    Log(cabal_log::NormalizeError),
    InvalidInput(&'static str),
}

impl std::fmt::Display for HookError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Observation(error) => write!(formatter, "observation error: {error}"),
            Self::Delta(error) => write!(formatter, "delta error: {error}"),
            Self::Log(error) => write!(formatter, "log error: {error}"),
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

impl From<std::io::Error> for HookError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
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

impl From<cabal_log::NormalizeError> for HookError {
    fn from(error: cabal_log::NormalizeError) -> Self {
        Self::Log(error)
    }
}

/// Rewrites a narrow, shell-free Cargo invocation to the native executor.
/// Unsupported command shapes are left untouched so the hook never changes
/// semantics it cannot reproduce without a shell.
pub fn prepare_pre_tool_use(
    input: PreToolUseInput,
    executable: &Path,
) -> Result<Option<PreToolUseOutput>, HookError> {
    if input.hook_event_name != "PreToolUse" {
        return Ok(None);
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(Value::as_str)
        .ok_or(HookError::InvalidInput("tool command is missing"))?;

    if let Some(output) = evaluate_change_policy(&input, command) {
        return Ok(Some(output));
    }
    if input.tool_name != "Bash" {
        return Ok(None);
    }

    let rewritten_command = if let Some(request) = parse_simple_cargo_command(command, &input.cwd) {
        let request_path = persist_execution_request(&input.cwd, &request)?;
        build_executor_command(executable, "execute-cargo", &request_path)
    } else if let Some(request) = parse_simple_log_command(command, &input.cwd) {
        let request_path = persist_execution_request(&input.cwd, &request)?;
        build_executor_command(executable, "execute-log", &request_path)
    } else if let Some(request) =
        parse_simple_file_read(command, &input.cwd, input.session_id.as_deref())
    {
        let request_path = persist_file_read_request(&input.cwd, &request)?;
        build_executor_command(executable, "execute-file-read", &request_path)
    } else if let Some(request) = parse_simple_git_command(command, &input.cwd) {
        let request_path = persist_git_execution_request(&input.cwd, &request)?;
        build_executor_command(executable, "execute-git", &request_path)
    } else {
        return Ok(None);
    };

    Ok(Some(PreToolUseOutput::rewrite(rewritten_command)))
}

fn evaluate_change_policy(input: &PreToolUseInput, command: &str) -> Option<PreToolUseOutput> {
    let policy_input = match input.tool_name.as_str() {
        "Bash" => ChangeToolInput::Bash(command),
        "apply_patch" => ChangeToolInput::ApplyPatch(command),
        _ => return None,
    };
    let evaluation = evaluate_change(&input.cwd, policy_input.clone());
    if evaluation.state == ChangePolicyState::Disabled {
        return None;
    }

    if let Some(receipt) = change_receipt_for(&evaluation, policy_input)
        && write_change_receipt(&input.cwd, &receipt).is_err()
    {
        return Some(PreToolUseOutput::deny("receipt_unavailable"));
    }

    match evaluation.decision {
        Some(ChangeDecision::Allow) | None => None,
        Some(ChangeDecision::Ask) => Some(PreToolUseOutput::deny("approval_required")),
        Some(ChangeDecision::Deny) => Some(PreToolUseOutput::deny(&evaluation.code)),
    }
}

/// Executes one bounded UTF-8 file observation without a shell.
pub fn execute_file_read_request(request_path: &Path) -> Result<String, HookError> {
    let raw_request = fs::read(request_path)?;
    let _ = fs::remove_file(request_path);
    let request = serde_json::from_slice::<FileReadExecutionRequest>(&raw_request)?;
    let workspace = fs::canonicalize(&request.cwd)?;
    let state_root = file_cache_root(&workspace);
    let observation = observe_file(
        &request.path,
        &workspace,
        &state_root,
        &request.session_id,
        request.requested,
    )
    .map_err(|_| HookError::InvalidInput("file observation failed"))?;
    serde_json::to_string(&ModelProjection::FileRead(observation)).map_err(Into::into)
}

pub fn invalidate_file_read_cache(cwd: &Path) -> Result<(), HookError> {
    let workspace = fs::canonicalize(cwd)?;
    invalidate_observations(&file_cache_root(&workspace))
        .map_err(|_| HookError::InvalidInput("file cache invalidation failed"))
}

/// Executes a contract-approved, read-only Git query without a shell.
pub fn execute_git_request(request_path: &Path) -> Result<String, HookError> {
    let request = serde_json::from_slice::<GitExecutionRequest>(&fs::read(request_path)?)?;
    let workspace = fs::canonicalize(&request.cwd)?;
    let artifact_root = git_runtime_root(&workspace).join("artifacts");
    let (query_name, args) = match &request.query {
        GitQuery::Status => (
            "status",
            vec![
                "--no-pager".to_owned(),
                "-c".to_owned(),
                "core.quotePath=false".to_owned(),
                "status".to_owned(),
                "--porcelain=v2".to_owned(),
                "-z".to_owned(),
                "--untracked-files=all".to_owned(),
                "--ignore-submodules=none".to_owned(),
            ],
        ),
        GitQuery::Diff => ("diff", safe_diff_args(false)),
        GitQuery::DiffCached => ("diff_cached", safe_diff_args(true)),
        GitQuery::Show { revision } => (
            "show",
            vec![
                "--no-pager".to_owned(),
                "-c".to_owned(),
                "core.quotePath=false".to_owned(),
                "show".to_owned(),
                "--format=".to_owned(),
                "--no-ext-diff".to_owned(),
                "--no-textconv".to_owned(),
                "--find-renames".to_owned(),
                "--unified=0".to_owned(),
                format!("{revision}^{{commit}}"),
                "--".to_owned(),
            ],
        ),
    };
    let output = Command::new("git")
        .args(&args)
        .current_dir(&workspace)
        .stdin(Stdio::null())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()?;
    let mut complete_raw = output.stdout.clone();
    if !output.stderr.is_empty() {
        complete_raw.extend_from_slice(b"\n--- stderr ---\n");
        complete_raw.extend_from_slice(&output.stderr);
    }
    persist_unclassified_raw(&complete_raw, &artifact_root)?;

    let projection = if !output.status.success() {
        unknown_git_projection(query_name, "Git query failed; no clean state is claimed")
    } else {
        match request.query {
            GitQuery::Status => normalize_status_bytes(&output.stdout, &artifact_root)
                .map(project_git_status)
                .unwrap_or_else(|_| {
                    unknown_git_projection(query_name, "Git status normalization failed")
                }),
            GitQuery::Diff | GitQuery::DiffCached | GitQuery::Show { .. } => {
                normalize_diff(&output.stdout, &artifact_root)
                    .map(|pack| project_git_diff(query_name, pack))
                    .unwrap_or_else(|_| {
                        unknown_git_projection(query_name, "Git diff normalization failed")
                    })
            }
        }
    };
    serde_json::to_string(&ModelProjection::Git(projection)).map_err(Into::into)
}

fn safe_diff_args(cached: bool) -> Vec<String> {
    let mut args = vec![
        "--no-pager".to_owned(),
        "-c".to_owned(),
        "core.quotePath=false".to_owned(),
        "diff".to_owned(),
        "--no-ext-diff".to_owned(),
        "--no-textconv".to_owned(),
        "--find-renames".to_owned(),
        "--unified=0".to_owned(),
    ];
    if cached {
        args.push("--cached".to_owned());
    }
    args.push("--".to_owned());
    args
}

/// Executes an approved report read or nextest invocation without a shell.
pub fn execute_log_request(request_path: &Path) -> Result<String, HookError> {
    let request = serde_json::from_slice::<LogExecutionRequest>(&fs::read(request_path)?)?;
    let artifact_root = artifact_root_for(&request.cwd);

    let (kind, raw, success) = match request.source {
        LogExecutionSource::File { path, kind } => {
            let workspace = fs::canonicalize(&request.cwd)?;
            let path = fs::canonicalize(path)?;
            if !path.starts_with(&workspace) || !path.is_file() {
                return Err(HookError::InvalidInput(
                    "report path is outside the workspace",
                ));
            }
            (kind, fs::read(path)?, true)
        }
        LogExecutionSource::Nextest { cargo_args } => {
            let output = Command::new("cargo")
                .args(&cargo_args)
                .current_dir(&request.cwd)
                .stdin(Stdio::null())
                .output()?;
            let mut raw = output.stdout;
            if !output.stderr.is_empty() {
                raw.extend_from_slice(b"\n--- stderr ---\n");
                raw.extend_from_slice(&output.stderr);
            }
            (LogInputKind::NextestText, raw, output.status.success())
        }
    };

    let projection = match normalize_log(kind, &raw, success, &artifact_root) {
        Ok(pack) => ModelProjection::Log(project_log(pack)),
        Err(_) => ModelProjection::Log(LogProjection {
            format: log_kind_name(kind).to_owned(),
            status: "normalization_failed".to_owned(),
            diagnostics: Vec::new(),
            counts: ModelLogCounts {
                total: 0,
                passed: 0,
                failed: 0,
                skipped: 0,
                errors: 0,
            },
            omitted: 0,
            completeness: "structured input was invalid; no semantic success is claimed".to_owned(),
        }),
    };

    serde_json::to_string(&projection).map_err(Into::into)
}

/// Executes an approved Cargo request without invoking a shell. The only data
/// written to stdout is the semantic projection; full process output stays in
/// the local artifact store.
pub fn execute_cargo_request(request_path: &Path) -> Result<String, HookError> {
    let request = serde_json::from_slice::<CargoExecutionRequest>(&fs::read(request_path)?)?;
    let artifact_root = artifact_root_for(&request.cwd);
    let completion_command = CompletionCargoCommand::new(request.receipt_args.clone());
    let contract_path = completion_contract_path(&request.cwd);
    let completion_state = completion_state_root(&request.cwd);

    // An attempted rerun invalidates an older success before process launch.
    update_completion_outcome(
        &contract_path,
        &request.cwd,
        &completion_state,
        &completion_command,
        CargoOutcome::Failed,
    )?;

    let output = Command::new("cargo")
        .args(&request.cargo_args)
        .current_dir(&request.cwd)
        .stdin(Stdio::null())
        .output()?;
    update_completion_outcome(
        &contract_path,
        &request.cwd,
        &completion_state,
        &completion_command,
        if output.status.success() {
            CargoOutcome::Succeeded
        } else {
            CargoOutcome::Failed
        },
    )?;

    let mut complete_raw = output.stdout.clone();
    if !output.stderr.is_empty() {
        complete_raw.extend_from_slice(b"\n--- stderr ---\n");
        complete_raw.extend_from_slice(&output.stderr);
    }
    persist_unclassified_raw(&complete_raw, &artifact_root)?;

    let mut projection = match request.kind {
        CargoExecutionKind::BuildJson => {
            normalize_observation(InputKind::CargoJson, &output.stdout, &artifact_root)
                .map(project_observation)
                .map(ModelProjection::Build)
                .unwrap_or_else(|_| {
                    generic_projection(status_from_success(output.status.success()))
                })
        }
        CargoExecutionKind::TestText => {
            normalize_observation(InputKind::CargoTestText, &complete_raw, &artifact_root)
                .map(project_observation)
                .map(ModelProjection::Test)
                .unwrap_or_else(|_| {
                    generic_projection(status_from_success(output.status.success()))
                })
        }
    };

    reconcile_process_status(&mut projection, output.status.success());

    serde_json::to_string(&projection).map_err(Into::into)
}
fn reconcile_process_status(projection: &mut ModelProjection, success: bool) {
    let (ModelProjection::Build(result) | ModelProjection::Test(result)) = projection else {
        return;
    };
    if result.status == "unknown" {
        result.status = if success { "passed" } else { "failed" }.to_owned();
    }
}

fn parse_simple_cargo_command(command: &str, cwd: &Path) -> Option<CargoExecutionRequest> {
    let words = command.split_whitespace().collect::<Vec<_>>();
    if words.is_empty() || words[0] != "cargo" || words.iter().any(|word| !is_safe_cargo_word(word))
    {
        return None;
    }

    let action_index = if words.get(1).is_some_and(|word| word.starts_with('+')) {
        2
    } else {
        1
    };
    let action = *words.get(action_index)?;
    let kind = match action {
        "build" | "check" | "clippy" => {
            if words.iter().any(|word| {
                word.starts_with("--message-format=") && *word != "--message-format=json"
            }) {
                return None;
            }
            CargoExecutionKind::BuildJson
        }
        "test" => CargoExecutionKind::TestText,
        _ => return None,
    };

    let receipt_args = words[1..]
        .iter()
        .map(|word| (*word).to_owned())
        .collect::<Vec<_>>();
    let mut cargo_args = receipt_args.clone();
    if kind == CargoExecutionKind::BuildJson
        && !cargo_args
            .iter()
            .any(|word| word == "--message-format=json")
    {
        let insert_at = cargo_args
            .iter()
            .position(|argument| argument == "--")
            .unwrap_or(cargo_args.len());
        cargo_args.insert(insert_at, "--message-format=json".to_owned());
    }

    Some(CargoExecutionRequest {
        cwd: cwd.to_path_buf(),
        cargo_args,
        receipt_args,
        kind,
    })
}

/// Evaluates an opt-in deterministic completion contract for a Codex Stop event.
pub fn evaluate_stop(input: StopInput) -> StopOutput {
    if input.hook_event_name != "Stop" {
        return stop_wire_failure();
    }
    if input.stop_hook_active {
        return StopOutput::pass();
    }
    let evaluation = evaluate_completion(
        &completion_contract_path(&input.cwd),
        &input.cwd,
        &completion_state_root(&input.cwd),
    );
    let reason = match evaluation.status {
        GateStatus::Pass => return StopOutput::pass(),
        GateStatus::Block => format!(
            "Completion evidence missing: {}.",
            evaluation.missing_ids.join(",")
        ),
        GateStatus::InvalidContract => {
            "Completion evidence unavailable: invalid_contract.".to_owned()
        }
        GateStatus::EvidenceUnavailable => {
            "Completion evidence unavailable: local_check_failed.".to_owned()
        }
    };
    StopOutput::block(reason)
}

pub fn stop_wire_failure() -> StopOutput {
    StopOutput::block("Completion evidence unavailable: invalid_hook_input.".to_owned())
}

fn update_completion_outcome(
    contract_path: &Path,
    workspace: &Path,
    state_root: &Path,
    command: &CompletionCargoCommand,
    outcome: CargoOutcome,
) -> Result<(), HookError> {
    match record_cargo_outcome(contract_path, workspace, state_root, command, outcome) {
        Ok(()) | Err(GateError::NoMatchingCriterion) => Ok(()),
        Err(_) => Err(HookError::InvalidInput("completion evidence update failed")),
    }
}

fn parse_simple_log_command(command: &str, cwd: &Path) -> Option<LogExecutionRequest> {
    let words = command.split_whitespace().collect::<Vec<_>>();
    if words.is_empty() || words.iter().any(|word| !is_safe_cargo_word(word)) {
        return None;
    }

    if words[0] == "cargo" {
        let action_index = if words.get(1).is_some_and(|word| word.starts_with('+')) {
            2
        } else {
            1
        };
        if words.get(action_index) == Some(&"nextest")
            && words.get(action_index + 1) == Some(&"run")
        {
            return Some(LogExecutionRequest {
                cwd: cwd.to_path_buf(),
                source: LogExecutionSource::Nextest {
                    cargo_args: words[1..].iter().map(|word| (*word).to_owned()).collect(),
                },
            });
        }
        return None;
    }

    let path_word = match words.as_slice() {
        ["cat", path] | ["Get-Content", path] | ["Get-Content", "-Raw", path] => *path,
        _ => return None,
    };
    let kind = infer_log_kind(path_word)?;
    let path = PathBuf::from(path_word);
    let path = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    Some(LogExecutionRequest {
        cwd: cwd.to_path_buf(),
        source: LogExecutionSource::File { path, kind },
    })
}

fn parse_simple_file_read(
    command: &str,
    cwd: &Path,
    session_id: Option<&str>,
) -> Option<FileReadExecutionRequest> {
    let words = split_simple_read_words(command)?;
    let (path, requested) = match words.as_slice() {
        [reader, path] if reader == "cat" || reader == "Get-Content" => {
            (path, RequestedRange::Full)
        }
        [reader, raw, path] if reader == "Get-Content" && raw == "-Raw" => {
            (path, RequestedRange::Full)
        }
        [reader, option, range, path] if reader == "sed" && option == "-n" => {
            (path, parse_sed_range(range)?)
        }
        _ => return None,
    };
    if infer_log_kind(path).is_some() {
        return None;
    }
    let path = PathBuf::from(path);
    let path = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    if !supports_request(&path, cwd, requested) {
        return None;
    }
    Some(FileReadExecutionRequest {
        cwd: cwd.to_path_buf(),
        path,
        session_id: session_id.unwrap_or("session-unavailable").to_owned(),
        requested,
    })
}

fn split_simple_read_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in command.chars() {
        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            Some('"') if matches!(character, '$' | '`') => return None,
            Some(_) => current.push(character),
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None if matches!(
                character,
                ';' | '|'
                    | '&'
                    | '>'
                    | '<'
                    | '`'
                    | '$'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '('
                    | ')'
            ) =>
            {
                return None;
            }
            None => current.push(character),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        words.push(current);
    }
    (!words.is_empty()).then_some(words)
}

fn parse_sed_range(value: &str) -> Option<RequestedRange> {
    let value = value.strip_suffix('p')?;
    let (start, end) = value.split_once(',')?;
    let start = start.parse().ok()?;
    let end = end.parse().ok()?;
    let requested = RequestedRange::Lines { start, end };
    (start > 0 && end >= start && end - start < cabal_file_cache::MAX_SLICE_LINES)
        .then_some(requested)
}

fn parse_simple_git_command(command: &str, cwd: &Path) -> Option<GitExecutionRequest> {
    let words = command.split_whitespace().collect::<Vec<_>>();
    let query = match words.as_slice() {
        ["git", "status"] => GitQuery::Status,
        ["git", "diff"] => GitQuery::Diff,
        ["git", "diff", "--cached"] => GitQuery::DiffCached,
        ["git", "show", revision] if is_safe_revision(revision) => GitQuery::Show {
            revision: (*revision).to_owned(),
        },
        _ => return None,
    };
    Some(GitExecutionRequest {
        cwd: cwd.to_path_buf(),
        query,
    })
}

fn is_safe_revision(revision: &str) -> bool {
    !revision.is_empty()
        && revision.len() <= 128
        && !revision.starts_with('-')
        && !revision.contains("..")
        && !revision.contains("^@")
        && !revision.contains("^!")
        && !revision.contains("^-")
        && revision.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-' | b'.' | b'/' | b'~' | b'^' | b'@' | b'{' | b'}' | b'+'
                )
        })
}

fn infer_log_kind(path: &str) -> Option<LogInputKind> {
    let path = path.to_ascii_lowercase();
    if path.ends_with(".junit.xml") || path.ends_with("junit-results.xml") {
        Some(LogInputKind::JunitXml)
    } else if path.ends_with(".sarif") || path.ends_with(".sarif.json") {
        Some(LogInputKind::SarifJson)
    } else if path.ends_with(".nextest.log") {
        Some(LogInputKind::NextestText)
    } else if path.ends_with(".log") {
        Some(LogInputKind::GenericText)
    } else {
        None
    }
}

fn is_safe_cargo_word(word: &str) -> bool {
    !word.is_empty()
        && word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-' | b'.' | b'/' | b'\\' | b':' | b'=' | b'+' | b',' | b'@'
                )
        })
}

fn persist_execution_request(cwd: &Path, request: &impl Serialize) -> Result<PathBuf, HookError> {
    let request_root = cwd.join(".cabal").join("requests");
    persist_request_at(&request_root, request)
}

fn persist_git_execution_request(
    cwd: &Path,
    request: &impl Serialize,
) -> Result<PathBuf, HookError> {
    persist_request_at(&git_runtime_root(cwd).join("requests"), request)
}

fn persist_file_read_request(cwd: &Path, request: &impl Serialize) -> Result<PathBuf, HookError> {
    persist_request_at(&file_cache_root(cwd).join("requests"), request)
}

fn persist_request_at(root: &Path, request: &impl Serialize) -> Result<PathBuf, HookError> {
    fs::create_dir_all(root)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HookError::InvalidInput("system clock is before Unix epoch"))?
        .as_nanos();
    let payload = serde_json::to_vec(request)?;
    let id = format!(
        "{:x}",
        Sha256::digest([payload.as_slice(), timestamp.to_string().as_bytes()].concat())
    );
    let path = root.join(format!("{id}.json"));
    fs::write(&path, payload)?;
    Ok(path)
}

fn git_runtime_root(cwd: &Path) -> PathBuf {
    let discovered = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .current_dir(cwd)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    if let Ok(output) = discovered
        && output.status.success()
        && let Ok(raw_path) = std::str::from_utf8(&output.stdout)
        && let Ok(git_dir) = fs::canonicalize(raw_path.trim())
        && git_dir.is_dir()
    {
        return git_dir.join("cabal-runtime");
    }
    cwd.join(".cabal").join("git-runtime")
}

fn file_cache_root(cwd: &Path) -> PathBuf {
    git_runtime_root(cwd).join("file-cache")
}

fn completion_contract_path(cwd: &Path) -> PathBuf {
    cwd.join(".cabal").join("completion").join("contract.json")
}

fn completion_state_root(cwd: &Path) -> PathBuf {
    git_runtime_root(cwd).join("completion")
}

fn build_executor_command(executable: &Path, subcommand: &str, request_path: &Path) -> String {
    let executable = executable.to_string_lossy();
    let request_path = request_path.to_string_lossy();
    if cfg!(windows) {
        format!(
            "& {} {} --request {}",
            quote_powershell(&executable),
            subcommand,
            quote_powershell(&request_path)
        )
    } else {
        format!(
            "{} {} --request {}",
            quote_posix_shell(&executable),
            subcommand,
            quote_posix_shell(&request_path)
        )
    }
}

fn project_log(pack: LogPack) -> LogProjection {
    LogProjection {
        format: log_kind_name(pack.kind).to_owned(),
        status: match pack.verdict {
            LogVerdict::Passed => "passed",
            LogVerdict::Failed => "failed",
            LogVerdict::Unknown => "unknown",
        }
        .to_owned(),
        diagnostics: pack
            .diagnostics
            .into_iter()
            .map(|diagnostic| ModelDiagnostic {
                kind: format!("{:?}", diagnostic.category).to_ascii_lowercase(),
                code: diagnostic.rule_id,
                suite: diagnostic.suite,
                test: diagnostic.test,
                message: diagnostic.message,
                location: diagnostic.file.as_ref().map(|file| {
                    format!(
                        "{}:{}:{}",
                        file,
                        diagnostic.line.unwrap_or(1),
                        diagnostic.column.unwrap_or(1)
                    )
                }),
                related_locations: diagnostic
                    .related_locations
                    .iter()
                    .filter_map(|location| {
                        location.file.as_ref().map(|file| {
                            format!(
                                "{}:{}:{}",
                                file,
                                location.line.unwrap_or(1),
                                location.column.unwrap_or(1)
                            )
                        })
                    })
                    .collect(),
            })
            .collect(),
        counts: ModelLogCounts {
            total: pack.counts.total,
            passed: pack.counts.passed,
            failed: pack.counts.failed,
            skipped: pack.counts.skipped,
            errors: pack.counts.errors,
        },
        omitted: pack.omitted.as_ref().map_or(0, |omitted| omitted.count),
        completeness: if pack.complete {
            "all supported semantic events retained".to_owned()
        } else {
            "bounded projection; omitted or contradictory input is reported".to_owned()
        },
    }
}

fn log_kind_name(kind: LogInputKind) -> &'static str {
    match kind {
        LogInputKind::JunitXml => "junit_xml",
        LogInputKind::SarifJson => "sarif_2_1_0",
        LogInputKind::GenericText => "generic_text_log",
        LogInputKind::NextestText => "nextest_text",
    }
}

fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_posix_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn status_from_success(success: bool) -> &'static str {
    if success { "completed" } else { "failed" }
}

/// Returns a bounded projection for every PostToolUse payload. The plugin
/// matcher may choose a narrower surface, while a core-side caller can use the
/// same fail-closed adapter for all built-in tool types.
pub fn project_post_tool_use(input: PostToolUseInput) -> Result<Option<HookOutput>, HookError> {
    if input.hook_event_name != "PostToolUse" {
        return Ok(None);
    }
    if is_existing_projection(&input.tool_response) {
        return Ok(Some(HookOutput {
            should_continue: false,
            stop_reason: serde_json::to_string(&input.tool_response)?,
        }));
    }
    let raw = response_bytes(&input.tool_response)?;
    let semantic_raw = strip_codex_output_wrapper(&raw);
    let artifact_root = input.cwd.join(".cabal").join("artifacts");

    if input.tool_name != "Bash" {
        let _ = persist_unclassified_raw(&raw, &artifact_root);
        return Ok(Some(HookOutput {
            should_continue: false,
            stop_reason: serde_json::to_string(&generic_projection("unknown"))?,
        }));
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(Value::as_str)
        .ok_or(HookError::InvalidInput("Bash command is missing"))?;

    let projection = if is_git_diff(command) {
        normalize_diff(semantic_raw, &artifact_root)
            .map(project_diff)
            .map(ModelProjection::Diff)
            .unwrap_or_else(|_| {
                let _ = persist_unclassified_raw(&raw, &artifact_root);
                generic_projection("normalization_failed")
            })
    } else if let Some(kind) = build_input_kind(command, semantic_raw) {
        normalize_observation(kind, semantic_raw, &artifact_root)
            .map(project_observation)
            .map(|projection| match kind {
                InputKind::CargoJson => ModelProjection::Build(projection),
                InputKind::CargoTestText => ModelProjection::Test(projection),
            })
            .unwrap_or_else(|_| {
                let _ = persist_unclassified_raw(&raw, &artifact_root);
                generic_projection("normalization_failed")
            })
    } else {
        let _ = persist_unclassified_raw(&raw, &artifact_root);
        generic_projection(command_status(&input.tool_response))
    };

    Ok(Some(HookOutput {
        should_continue: false,
        stop_reason: serde_json::to_string(&projection)?,
    }))
}

fn is_existing_projection(response: &Value) -> bool {
    response
        .as_object()
        .is_some_and(|object| object.contains_key("operation") && object.contains_key("result"))
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

/// Codex shell adapters may prepend an execution receipt before stdout. The
/// receipt is not command output and would make Cargo JSON or unified-diff
/// detection fail. Only an initial `Wall time:` header is stripped; ordinary
/// user output containing `Output:` is left untouched.
fn strip_codex_output_wrapper(raw: &[u8]) -> &[u8] {
    if !raw.starts_with(b"Wall time:") {
        return raw;
    }

    for marker in [b"\nOutput:\n".as_slice(), b"\r\nOutput:\r\n".as_slice()] {
        if let Some(offset) = raw
            .windows(marker.len())
            .position(|window| window == marker)
        {
            return &raw[offset + marker.len()..];
        }
    }
    raw
}

fn persist_unclassified_raw(raw: &[u8], artifact_root: &Path) -> std::io::Result<()> {
    let artifact_id = format!("{:x}", Sha256::digest(raw));
    let artifact_dir = artifact_root.join(artifact_id);
    fs::create_dir_all(&artifact_dir)?;
    let artifact_path = artifact_dir.join("raw-output");
    if !artifact_path.exists() {
        fs::write(artifact_path, raw)?;
    }
    Ok(())
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
                suite: None,
                test: None,
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

fn project_git_diff(query: &str, pack: DeltaPack) -> GitProjection {
    let status = match pack.verdict {
        cabal_delta::DeltaVerdict::Clean => "clean",
        cabal_delta::DeltaVerdict::Changed => "changed",
    }
    .to_owned();
    let files = pack
        .files
        .into_iter()
        .map(|file| {
            let path = file
                .new_path
                .clone()
                .or_else(|| file.old_path.clone())
                .unwrap_or_default();
            let change_kind = format!("{:?}", file.change_kind).to_ascii_lowercase();
            ModelGitFile {
                path,
                old_path: file.old_path,
                change_kind: Some(change_kind.clone()),
                classification: format!("{:?}", file.classification).to_ascii_lowercase(),
                index_status: (query == "diff_cached").then(|| change_kind.clone()),
                worktree_status: (query == "diff").then_some(change_kind),
                untracked: false,
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
            }
        })
        .collect();
    GitProjection {
        query: query.to_owned(),
        status,
        files,
        summary: ModelGitSummary {
            files_changed: pack.summary.files_changed,
            files_added: pack.summary.files_added,
            files_deleted: pack.summary.files_deleted,
            files_renamed: pack.summary.files_renamed,
            binary_files: pack.summary.binary_files,
            additions: pack.summary.additions,
            deletions: pack.summary.deletions,
            staged: if query == "diff_cached" {
                pack.summary.files_changed
            } else {
                0
            },
            unstaged: if query == "diff" {
                pack.summary.files_changed
            } else {
                0
            },
            ..ModelGitSummary::default()
        },
        omitted_files: pack.omitted_files,
        omitted_hunks: pack.omitted_hunks,
        completeness: pack.completeness,
    }
}

fn project_git_status(pack: GitStatusPack) -> GitProjection {
    let files = pack
        .entries
        .into_iter()
        .map(|entry| ModelGitFile {
            path: entry.path,
            old_path: entry.original_path,
            change_kind: None,
            classification: format!("{:?}", entry.classification).to_ascii_lowercase(),
            index_status: entry.index_status.map(status_kind_name),
            worktree_status: entry.worktree_status.map(status_kind_name),
            untracked: entry.untracked,
            binary: false,
            hunks: Vec::new(),
            additions: 0,
            deletions: 0,
        })
        .collect();
    GitProjection {
        query: "status".to_owned(),
        status: if pack.summary.files_changed == 0 {
            "clean"
        } else {
            "changed"
        }
        .to_owned(),
        files,
        summary: ModelGitSummary {
            files_changed: pack.summary.files_changed,
            staged: pack.summary.staged,
            unstaged: pack.summary.unstaged,
            untracked: pack.summary.untracked,
            conflicts: pack.summary.conflicts,
            ..ModelGitSummary::default()
        },
        omitted_files: pack.omitted_files,
        omitted_hunks: 0,
        completeness: pack.completeness,
    }
}

fn unknown_git_projection(query: &str, completeness: &str) -> GitProjection {
    GitProjection {
        query: query.to_owned(),
        status: "unknown".to_owned(),
        files: Vec::new(),
        summary: ModelGitSummary::default(),
        omitted_files: 0,
        omitted_hunks: 0,
        completeness: completeness.to_owned(),
    }
}

fn status_kind_name(kind: StatusKind) -> String {
    format!("{kind:?}").to_ascii_lowercase()
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
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
        assert!(artifact_root_for(workspace.path()).exists());
    }

    #[test]
    fn non_bash_payloads_fail_closed_to_a_bounded_projection() {
        let workspace = tempfile::tempdir().unwrap();
        let input = PostToolUseInput {
            hook_event_name: "PostToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "WebSearch".to_owned(),
            tool_input: serde_json::json!({ "query": "ignored" }),
            tool_response: Value::String("private-search-result".to_owned()),
        };

        let output = project_post_tool_use(input).unwrap().unwrap();

        assert!(!output.should_continue);
        assert!(output.stop_reason.contains("\"operation\":\"command\""));
        assert!(!output.stop_reason.contains("private-search-result"));
        assert!(artifact_root_for(workspace.path()).exists());
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

    #[test]
    fn strips_only_the_codex_execution_wrapper_before_cargo_normalization() {
        let workspace = tempfile::tempdir().unwrap();
        let raw =
            "Wall time: 0.01 seconds\nOutput:\n{\"reason\":\"build-finished\",\"success\":true}\n";

        let output = project_post_tool_use(bash_input(
            "cargo check --message-format=json",
            raw,
            workspace.path(),
        ))
        .unwrap()
        .unwrap();

        assert!(output.stop_reason.contains("\"operation\":\"build\""));
        assert!(output.stop_reason.contains("\"status\":\"passed\""));
        assert!(!output.stop_reason.contains("Wall time"));
    }

    #[test]
    fn preserves_an_existing_projection_across_a_second_post_tool_use_pass() {
        let workspace = tempfile::tempdir().unwrap();
        let projection = serde_json::json!({
            "operation": "build",
            "result": { "status": "passed", "completeness": "Complete." }
        });
        let input = PostToolUseInput {
            hook_event_name: "PostToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "Bash".to_owned(),
            tool_input: serde_json::json!({ "command": "cargo check" }),
            tool_response: projection.clone(),
        };

        let output = project_post_tool_use(input).unwrap().unwrap();

        assert_eq!(
            serde_json::from_str::<Value>(&output.stop_reason).unwrap(),
            projection
        );
    }

    #[test]
    fn rewrites_only_a_simple_supported_cargo_command() {
        let workspace = tempfile::tempdir().unwrap();
        let original = "cargo +nightly test -p cabal-runtime-hook";
        let input = PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "Bash".to_owned(),
            tool_input: serde_json::json!({ "command": original }),
            session_id: None,
        };

        let output = prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
            .unwrap()
            .unwrap();
        let serialized = serde_json::to_string(&output).unwrap();

        assert!(!serialized.contains(original));
        assert!(serialized.contains("execute-cargo"));
        let request = fs::read_dir(workspace.path().join(".cabal/requests"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let request =
            serde_json::from_slice::<CargoExecutionRequest>(&fs::read(request.path()).unwrap())
                .unwrap();
        assert_eq!(
            request.cargo_args,
            ["+nightly", "test", "-p", "cabal-runtime-hook"]
        );
        assert_eq!(request.receipt_args, request.cargo_args);
        assert_eq!(request.kind, CargoExecutionKind::TestText);
    }

    #[test]
    fn inserts_json_format_before_clippy_rustc_arguments() {
        let request =
            parse_simple_cargo_command("cargo +nightly clippy -- -D warnings", Path::new("."))
                .unwrap();

        assert_eq!(
            request.cargo_args,
            [
                "+nightly",
                "clippy",
                "--message-format=json",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert_eq!(
            request.receipt_args,
            ["+nightly", "clippy", "--", "-D", "warnings"]
        );
    }

    #[test]
    fn completion_stop_returns_valid_pass_json_without_contract_and_on_recursion() {
        let workspace = tempfile::tempdir().unwrap();
        for output in [
            evaluate_stop(StopInput {
                hook_event_name: "Stop".to_owned(),
                cwd: workspace.path().to_path_buf(),
                stop_hook_active: false,
            }),
            {
                fs::create_dir_all(workspace.path().join(".cabal/completion")).unwrap();
                fs::write(
                    workspace.path().join(".cabal/completion/contract.json"),
                    r#"{"version":1,"criteria":[{"id":"tests","type":"file_exists","path":"missing"}]}"#,
                )
                .unwrap();
                evaluate_stop(StopInput {
                    hook_event_name: "Stop".to_owned(),
                    cwd: workspace.path().to_path_buf(),
                    stop_hook_active: true,
                })
            },
        ] {
            assert_eq!(
                serde_json::to_string(&output).unwrap(),
                r#"{"continue":true}"#
            );
        }
    }

    #[test]
    fn completion_stop_blocks_with_only_bounded_safe_ids() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join(".cabal/completion")).unwrap();
        fs::write(
            workspace.path().join(".cabal/completion/contract.json"),
            r#"{"version":1,"criteria":[{"id":"cargo-test","type":"file_exists","path":"missing"}]}"#,
        )
        .unwrap();
        let output = evaluate_stop(StopInput {
            hook_event_name: "Stop".to_owned(),
            cwd: workspace.path().to_path_buf(),
            stop_hook_active: false,
        });
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(
            json,
            r#"{"decision":"block","reason":"Completion evidence missing: cargo-test."}"#
        );
        assert!(!json.contains(".cabal"));
        assert!(!json.contains("sha256"));
    }

    #[test]
    fn completion_stop_sanitizes_malformed_contract_errors() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join(".cabal/completion")).unwrap();
        fs::write(
            workspace.path().join(".cabal/completion/contract.json"),
            "{private-path-and-parser-details",
        )
        .unwrap();
        let output = evaluate_stop(StopInput {
            hook_event_name: "Stop".to_owned(),
            cwd: workspace.path().to_path_buf(),
            stop_hook_active: false,
        });
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("invalid_contract"));
        assert!(!json.contains("private-path"));
        assert!(!json.contains("parser"));
    }

    #[test]
    fn native_cargo_execution_records_and_refreshes_completion_receipt() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join("src")).unwrap();
        fs::create_dir_all(workspace.path().join(".cabal/completion")).unwrap();
        fs::write(
            workspace.path().join("Cargo.toml"),
            "[package]\nname = \"completion-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join(".cabal/completion/contract.json"),
            r#"{"version":1,"criteria":[{"id":"cargo-check","type":"command_receipt","program":"cargo","args":["check"],"input_paths":["Cargo.toml","src"]}]}"#,
        )
        .unwrap();

        let request = parse_simple_cargo_command("cargo check", workspace.path()).unwrap();
        let request_path = persist_execution_request(workspace.path(), &request).unwrap();
        let projection = execute_cargo_request(&request_path).unwrap();
        assert!(projection.contains("\"status\":\"passed\""));
        assert_eq!(
            serde_json::to_string(&evaluate_stop(StopInput {
                hook_event_name: "Stop".to_owned(),
                cwd: workspace.path().to_path_buf(),
                stop_hook_active: false,
            }))
            .unwrap(),
            r#"{"continue":true}"#
        );

        fs::write(
            workspace.path().join("src/lib.rs"),
            "pub fn value() -> MissingType { todo!() }\n",
        )
        .unwrap();
        let request = parse_simple_cargo_command("cargo check", workspace.path()).unwrap();
        let request_path = persist_execution_request(workspace.path(), &request).unwrap();
        let projection = execute_cargo_request(&request_path).unwrap();
        assert!(projection.contains("\"status\":\"failed\""));
        let blocked = evaluate_stop(StopInput {
            hook_event_name: "Stop".to_owned(),
            cwd: workspace.path().to_path_buf(),
            stop_hook_active: false,
        });
        assert_eq!(
            blocked.reason.as_deref(),
            Some("Completion evidence missing: cargo-check.")
        );
    }
    #[test]
    fn leaves_shell_composition_and_non_json_build_formats_untouched() {
        let workspace = tempfile::tempdir().unwrap();
        for command in [
            "cargo test; echo leaked",
            "cargo check --message-format=human",
            "rg Cabal",
        ] {
            let input = PreToolUseInput {
                hook_event_name: "PreToolUse".to_owned(),
                cwd: workspace.path().to_path_buf(),
                tool_name: "Bash".to_owned(),
                tool_input: serde_json::json!({ "command": command }),
                session_id: None,
            };
            assert!(
                prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn test_projection_uses_a_test_operation_tag() {
        let projection = ModelProjection::Test(BuildProjection {
            status: "passed".to_owned(),
            diagnostics: Vec::new(),
            tests: Some(ModelTests {
                passed: Some(1),
                failed: Some(0),
                ignored: Some(0),
            }),
            completeness: "Complete.".to_owned(),
        });

        let serialized = serde_json::to_string(&projection).unwrap();
        assert!(serialized.contains("\"operation\":\"test\""));
    }
    #[test]
    fn successful_process_resolves_unknown_projection_to_passed() {
        let mut projection = ModelProjection::Build(BuildProjection {
            status: "unknown".to_owned(),
            diagnostics: Vec::new(),
            tests: None,
            completeness: "Complete.".to_owned(),
        });
        reconcile_process_status(&mut projection, true);
        let ModelProjection::Build(result) = projection else {
            panic!("expected build projection");
        };
        assert_eq!(result.status, "passed");
    }

    #[test]
    fn failed_process_resolves_unknown_projection_to_failed() {
        let mut projection = ModelProjection::Test(BuildProjection {
            status: "unknown".to_owned(),
            diagnostics: Vec::new(),
            tests: None,
            completeness: "Complete.".to_owned(),
        });
        reconcile_process_status(&mut projection, false);
        let ModelProjection::Test(result) = projection else {
            panic!("expected test projection");
        };
        assert_eq!(result.status, "failed");
    }

    #[test]
    fn rewrites_a_supported_report_read_to_the_log_executor() {
        let workspace = tempfile::tempdir().unwrap();
        let report = workspace.path().join("results.junit.xml");
        fs::write(&report, "<testsuite/>").unwrap();
        let input = PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "Bash".to_owned(),
            tool_input: serde_json::json!({
                "command": "Get-Content results.junit.xml"
            }),
            session_id: None,
        };

        let output = prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
            .unwrap()
            .unwrap();
        let serialized = serde_json::to_string(&output).unwrap();

        assert!(serialized.contains("execute-log"));
        assert!(!serialized.contains("Get-Content"));
        let request = fs::read_dir(workspace.path().join(".cabal/requests"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let request =
            serde_json::from_slice::<LogExecutionRequest>(&fs::read(request.path()).unwrap())
                .unwrap();
        assert_eq!(
            request.source,
            LogExecutionSource::File {
                path: report,
                kind: LogInputKind::JunitXml
            }
        );
    }

    #[test]
    fn report_grammar_rejects_composition_and_unknown_suffixes() {
        let workspace = tempfile::tempdir().unwrap();
        for command in [
            "Get-Content results.junit.xml; echo leaked",
            "cat report.xml",
            "Get-Content report.txt",
            "cargo nextest run && echo leaked",
        ] {
            let input = PreToolUseInput {
                hook_event_name: "PreToolUse".to_owned(),
                cwd: workspace.path().to_path_buf(),
                tool_name: "Bash".to_owned(),
                tool_input: serde_json::json!({ "command": command }),
                session_id: None,
            };
            assert!(
                prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn executes_junit_read_without_returning_raw_or_artifact_metadata() {
        let workspace = tempfile::tempdir().unwrap();
        let report = workspace.path().join("results.junit.xml");
        let raw = format!(
            r#"<testsuite name="integration"><testcase name="fails"><failure message="assertion failed" file="src/lib.rs" line="9"/></testcase><system-out>UNIQUE_RAW_MARKER{}</system-out></testsuite>"#,
            "x".repeat(10_000)
        );
        fs::write(&report, &raw).unwrap();
        let request = LogExecutionRequest {
            cwd: workspace.path().to_path_buf(),
            source: LogExecutionSource::File {
                path: report,
                kind: LogInputKind::JunitXml,
            },
        };
        let request_path = persist_execution_request(workspace.path(), &request).unwrap();

        let projection = execute_log_request(&request_path).unwrap();

        assert!(projection.contains("\"operation\":\"log\""));
        assert!(projection.contains("\"format\":\"junit_xml\""));
        assert!(projection.contains("\"suite\":\"integration\""));
        assert!(projection.contains("\"test\":\"fails\""));
        assert!(projection.contains("src/lib.rs:9:1"));
        assert!(!projection.contains("UNIQUE_RAW_MARKER"));
        assert!(!projection.contains("artifact"));
        assert!(!projection.contains("sha256"));
        assert!(!projection.contains("cabal"));
        assert!(projection.len() * 10 < raw.len());
    }

    #[test]
    fn malformed_structured_report_never_claims_success() {
        let workspace = tempfile::tempdir().unwrap();
        let report = workspace.path().join("broken.junit.xml");
        fs::write(&report, "<testsuite>").unwrap();
        let request = LogExecutionRequest {
            cwd: workspace.path().to_path_buf(),
            source: LogExecutionSource::File {
                path: report,
                kind: LogInputKind::JunitXml,
            },
        };
        let request_path = persist_execution_request(workspace.path(), &request).unwrap();

        let projection = execute_log_request(&request_path).unwrap();

        assert!(projection.contains("normalization_failed"));
        assert!(!projection.contains("\"status\":\"passed\""));
    }

    #[test]
    fn log_executor_rejects_files_outside_the_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let request = LogExecutionRequest {
            cwd: workspace.path().to_path_buf(),
            source: LogExecutionSource::File {
                path: outside.path().to_path_buf(),
                kind: LogInputKind::GenericText,
            },
        };
        let request_path = persist_execution_request(workspace.path(), &request).unwrap();

        assert!(matches!(
            execute_log_request(&request_path),
            Err(HookError::InvalidInput(
                "report path is outside the workspace"
            ))
        ));
    }

    #[test]
    fn recognizes_simple_nextest_without_shell_composition() {
        let request = parse_simple_log_command(
            "cargo +nightly nextest run -p cabal-runtime-hook",
            Path::new("."),
        )
        .unwrap();

        assert_eq!(
            request.source,
            LogExecutionSource::Nextest {
                cargo_args: vec![
                    "+nightly".to_owned(),
                    "nextest".to_owned(),
                    "run".to_owned(),
                    "-p".to_owned(),
                    "cabal-runtime-hook".to_owned(),
                ]
            }
        );
    }

    #[test]
    fn git_grammar_is_exact_and_rejects_composition_ranges_and_flags() {
        for (command, expected) in [
            ("git status", GitQuery::Status),
            ("git diff", GitQuery::Diff),
            ("git diff --cached", GitQuery::DiffCached),
            (
                "git show HEAD~1",
                GitQuery::Show {
                    revision: "HEAD~1".to_owned(),
                },
            ),
        ] {
            assert_eq!(
                parse_simple_git_command(command, Path::new("."))
                    .unwrap()
                    .query,
                expected
            );
        }
        for command in [
            "git status --short",
            "git diff --stat",
            "git diff -- src/lib.rs",
            "git diff && echo leaked",
            "git show --stat",
            "git show HEAD..main",
            "git show --output=leak HEAD",
            "git show HEAD:src/lib.rs",
        ] {
            assert!(parse_simple_git_command(command, Path::new(".")).is_none());
        }
    }

    #[test]
    fn git_gateway_is_read_only_and_excludes_patch_bodies() {
        let workspace = tempfile::tempdir().unwrap();
        run_git(workspace.path(), &["init", "-q"]);
        run_git(
            workspace.path(),
            &["config", "user.email", "cabal@example.invalid"],
        );
        run_git(workspace.path(), &["config", "user.name", "Cabal Test"]);
        fs::create_dir_all(workspace.path().join("src")).unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            "pub fn original() {}\n",
        )
        .unwrap();
        fs::write(workspace.path().join("old name.rs"), "fn old() {}\n").unwrap();
        run_git(workspace.path(), &["add", "."]);
        run_git(workspace.path(), &["commit", "-qm", "initial"]);

        let noisy_change = format!(
            "pub fn changed() {{ /* RAW_UNSTAGED_PATCH_MARKER {} */ }}\n",
            "x".repeat(10_000)
        );
        fs::write(workspace.path().join("src/lib.rs"), noisy_change).unwrap();
        run_git(workspace.path(), &["mv", "old name.rs", "юникод name.rs"]);
        fs::write(
            workspace.path().join("Cargo.toml"),
            "# RAW_UNTRACKED_MARKER\n",
        )
        .unwrap();

        let before = git_state(workspace.path());
        let raw_diff = run_git(
            workspace.path(),
            &["diff", "--no-ext-diff", "--no-textconv"],
        );
        let status = execute_git(workspace.path(), GitQuery::Status);
        let diff = execute_git(workspace.path(), GitQuery::Diff);
        let cached = execute_git(workspace.path(), GitQuery::DiffCached);
        let show = execute_git(
            workspace.path(),
            GitQuery::Show {
                revision: "HEAD".to_owned(),
            },
        );
        let after = git_state(workspace.path());

        assert_eq!(before, after);
        assert!(status.contains("\"operation\":\"git\""));
        assert!(status.contains("\"query\":\"status\""));
        assert!(status.contains("Cargo.toml"));
        assert!(status.contains("\"classification\":\"manifest\""));
        assert!(status.contains("юникод name.rs"));
        assert!(status.contains("\"staged\":1"));
        assert!(status.contains("\"unstaged\":1"));
        assert!(status.contains("\"untracked\":1"));
        assert!(diff.contains("src/lib.rs"));
        assert!(diff.contains("\"unstaged\":1"));
        assert!(!diff.contains("RAW_UNSTAGED_PATCH_MARKER"));
        assert!(diff.len() * 10 < raw_diff.len());
        assert!(cached.contains("юникод name.rs"));
        assert!(cached.contains("\"staged\":1"));
        assert!(!cached.contains("fn old"));
        assert!(show.contains("\"query\":\"show\""));
        assert!(!show.contains("pub fn original"));
        for projection in [&status, &diff, &cached, &show] {
            assert!(!projection.contains("artifact"));
            assert!(!projection.contains("sha256"));
            assert!(!projection.contains(".cabal"));
        }
    }

    #[test]
    fn file_read_grammar_is_exact_bounded_and_does_not_steal_logs() {
        let workspace = tempfile::tempdir().unwrap();
        let text = workspace.path().join("unicode file.txt");
        fs::write(&text, "one\ntwo\nthree\n").unwrap();
        let log = workspace.path().join("build.log");
        fs::write(&log, "error\n").unwrap();
        let binary = workspace.path().join("binary.bin");
        fs::write(&binary, [0xff, 0xfe]).unwrap();

        for (command, requested) in [
            ("cat 'unicode file.txt'", RequestedRange::Full),
            ("Get-Content \"unicode file.txt\"", RequestedRange::Full),
            ("Get-Content -Raw 'unicode file.txt'", RequestedRange::Full),
            (
                "sed -n '2,3p' 'unicode file.txt'",
                RequestedRange::Lines { start: 2, end: 3 },
            ),
        ] {
            let request =
                parse_simple_file_read(command, workspace.path(), Some("session")).unwrap();
            assert_eq!(request.requested, requested);
            assert_eq!(request.path, text);
        }

        for command in [
            "cat build.log",
            "cat binary.bin",
            "cat unicode file.txt",
            "cat *.txt",
            "cat file.txt | head",
            "Get-Content file.txt; echo leaked",
            "sed -n '0,2p' file.txt",
            "sed -n '1,401p' file.txt",
            "sed -n '1p' file.txt",
        ] {
            assert!(parse_simple_file_read(command, workspace.path(), Some("session")).is_none());
        }
    }

    #[test]
    fn file_read_gateway_refreshes_by_session_change_and_invalidation() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("large file.txt");
        let first_content = format!("header\n{}\nfooter\n", "x".repeat(10_000));
        fs::write(&path, &first_content).unwrap();

        let first = execute_file_read(workspace.path(), &path, "session-a", RequestedRange::Full);
        let unchanged =
            execute_file_read(workspace.path(), &path, "session-a", RequestedRange::Full);
        assert!(first.contains("\"status\":\"content\""));
        assert!(first.contains("header\\n"));
        assert!(unchanged.contains("\"status\":\"unchanged\""));
        assert!(!unchanged.contains(&"x".repeat(100)));
        assert!(unchanged.len() * 10 < first.len());

        let changed_content = format!("header\n{}\nfooter changed\n", "y".repeat(10_000));
        fs::write(&path, &changed_content).unwrap();
        let changed = execute_file_read(workspace.path(), &path, "session-a", RequestedRange::Full);
        assert!(changed.contains("\"status\":\"changed\""));
        assert!(changed.contains("footer changed"));
        assert!(changed.contains("changed_ranges"));

        let new_session =
            execute_file_read(workspace.path(), &path, "session-b", RequestedRange::Full);
        assert!(new_session.contains("\"status\":\"content\""));

        invalidate_file_read_cache(workspace.path()).unwrap();
        let after_compact =
            execute_file_read(workspace.path(), &path, "session-a", RequestedRange::Full);
        assert!(after_compact.contains("\"status\":\"content\""));
        for projection in [&first, &unchanged, &changed, &new_session, &after_compact] {
            assert!(!projection.contains("sha256"));
            assert!(!projection.contains("snapshots"));
            assert!(!projection.contains(".cabal"));
        }
    }

    #[test]
    fn pre_tool_use_rewrites_supported_file_read_to_native_executor() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join("notes.txt"), "visible\n").unwrap();
        let input = PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "Bash".to_owned(),
            tool_input: serde_json::json!({ "command": "cat notes.txt" }),
            session_id: Some("session-42".to_owned()),
        };

        let output = prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
            .unwrap()
            .unwrap();
        let serialized = serde_json::to_string(&output).unwrap();

        assert!(serialized.contains("execute-file-read"));
        assert!(!serialized.contains("cat notes.txt"));
    }

    #[test]
    fn change_policy_is_inert_when_absent_and_silent_when_allowed() {
        let workspace = tempfile::tempdir().unwrap();
        let patch =
            "*** Begin Patch\n*** Add File: src/lib.rs\n+pub fn value() {}\n*** End Patch\n";
        let input = PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "apply_patch".to_owned(),
            tool_input: serde_json::json!({"command": patch}),
            session_id: None,
        };
        assert!(
            prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                .unwrap()
                .is_none()
        );

        write_change_policy(
            workspace.path(),
            serde_json::json!({
                "version": 1,
                "paths": {"allow": ["src/**"]}
            }),
        );
        let input = PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "apply_patch".to_owned(),
            tool_input: serde_json::json!({"command": patch}),
            session_id: None,
        };
        assert!(
            prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                .unwrap()
                .is_none()
        );
        assert!(
            workspace
                .path()
                .join(".cabal/state/change_policy/receipts")
                .is_dir()
        );
    }

    #[test]
    fn change_policy_denies_before_patch_and_exposes_only_safe_code() {
        let workspace = tempfile::tempdir().unwrap();
        write_change_policy(
            workspace.path(),
            serde_json::json!({
                "version": 1,
                "paths": {"deny": ["secrets/**"]}
            }),
        );
        let patch = "*** Begin Patch\n*** Add File: secrets/key\n+raw-secret\n*** End Patch\n";
        let input = PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.path().to_path_buf(),
            tool_name: "apply_patch".to_owned(),
            tool_input: serde_json::json!({"command": patch}),
            session_id: None,
        };
        let output = prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
            .unwrap()
            .unwrap();
        let wire = serde_json::to_value(output).unwrap();
        let specific = &wire["hookSpecificOutput"];
        assert_eq!(specific["permissionDecision"], "deny");
        assert_eq!(
            specific["permissionDecisionReason"],
            "Change blocked by policy: path_denied."
        );
        assert!(specific.get("updatedInput").is_none());
        let encoded = serde_json::to_string(&wire).unwrap();
        assert!(!encoded.contains("secrets/key"));
        assert!(!encoded.contains("raw-secret"));
        assert!(!workspace.path().join("secrets/key").exists());
    }

    #[test]
    fn change_policy_maps_ask_to_deny_and_malformed_policy_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        write_change_policy(
            workspace.path(),
            serde_json::json!({
                "version": 1,
                "commands": {"ask": [["cargo", "fmt"]]}
            }),
        );
        let input = pre_tool_bash(workspace.path(), "cargo fmt");
        let wire = serde_json::to_value(
            prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            wire["hookSpecificOutput"]["permissionDecisionReason"],
            "Change blocked by policy: approval_required."
        );

        fs::write(
            workspace
                .path()
                .join(cabal_change_policy::POLICY_RELATIVE_PATH),
            b"not json",
        )
        .unwrap();
        let input = pre_tool_bash(workspace.path(), "git reset --hard");
        let wire = serde_json::to_value(
            prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            wire["hookSpecificOutput"]["permissionDecisionReason"],
            "Change blocked by policy: invalid_policy."
        );

        let input = pre_tool_bash(workspace.path(), "cargo test");
        let wire = serde_json::to_value(
            prepare_pre_tool_use(input, Path::new("/opt/cabal-runtime-hook"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(wire["hookSpecificOutput"]["permissionDecision"], "allow");
        assert!(
            wire["hookSpecificOutput"]["updatedInput"]["command"]
                .as_str()
                .unwrap()
                .contains("execute-cargo")
        );
    }

    fn write_change_policy(workspace: &Path, policy: serde_json::Value) {
        let path = workspace.join(cabal_change_policy::POLICY_RELATIVE_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(&policy).unwrap()).unwrap();
    }

    fn pre_tool_bash(workspace: &Path, command: &str) -> PreToolUseInput {
        PreToolUseInput {
            hook_event_name: "PreToolUse".to_owned(),
            cwd: workspace.to_path_buf(),
            tool_name: "Bash".to_owned(),
            tool_input: serde_json::json!({"command": command}),
            session_id: None,
        }
    }

    fn execute_file_read(
        cwd: &Path,
        path: &Path,
        session_id: &str,
        requested: RequestedRange,
    ) -> String {
        let request = FileReadExecutionRequest {
            cwd: cwd.to_path_buf(),
            path: path.to_path_buf(),
            session_id: session_id.to_owned(),
            requested,
        };
        let request_path = persist_file_read_request(cwd, &request).unwrap();
        execute_file_read_request(&request_path).unwrap()
    }

    fn execute_git(cwd: &Path, query: GitQuery) -> String {
        let request = GitExecutionRequest {
            cwd: cwd.to_path_buf(),
            query,
        };
        let request_path = persist_git_execution_request(cwd, &request).unwrap();
        execute_git_request(&request_path).unwrap()
    }

    fn run_git(cwd: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn git_state(cwd: &Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            run_git(cwd, &["rev-parse", "HEAD"]),
            run_git(
                cwd,
                &["status", "--porcelain=v2", "-z", "--untracked-files=all"],
            ),
            run_git(cwd, &["diff", "--cached", "--binary"]),
        )
    }
}
