//! Deterministic, opt-in policy evaluation for supported change proposals.
//!
//! The crate never executes a shell command or mutates a proposed patch. A hook
//! adapter may translate an [`Evaluation`] into its host permission response.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::OpenOptions,
    io,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_RELATIVE_PATH: &str = ".cabal/policy/change_policy.json";
pub const MAX_POLICY_BYTES: usize = 65_536;
pub const MAX_PATCH_BYTES: usize = 1_048_576;
pub const MAX_PATCH_FILES: usize = 256;
pub const MAX_PATCH_LINE_CHANGES: usize = 200_000;
pub const MAX_COMMAND_BYTES: usize = 4_096;
pub const MAX_COMMAND_ARGS: usize = 32;
pub const MAX_COMMAND_ARG_BYTES: usize = 256;
pub const MAX_REASON_BYTES: usize = 256;
pub const MAX_CODE_BYTES: usize = 64;
pub const MAX_PATTERNS_PER_CLASS: usize = 64;
pub const MAX_COMMANDS_PER_CLASS: usize = 64;
pub const MAX_RECEIPTS: usize = 1_024;

static RECEIPT_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Disabled,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Evaluation {
    pub state: PolicyState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    pub code: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyLoad {
    Disabled,
    Active(Box<ChangePolicy>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangePolicy {
    digest: String,
    paths: PathRules,
    limits: Limits,
    commands: CommandRules,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolInput<'a> {
    ApplyPatch(&'a str),
    Bash(&'a str),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub policy_digest: String,
    pub input_kind: ReceiptKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    pub code: String,
    pub input_digest: String,
    pub created_unix_ms: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ApplyPatch,
    Bash,
}

#[derive(Debug)]
pub enum PolicyError {
    Io(io::Error),
    Json(serde_json::Error),
    PolicyOutsideWorkspace,
    PolicyTooLarge,
    MalformedPolicy(String),
    UnsupportedPolicy(String),
    StateOutsideWorkspace,
    InvalidPath(String),
    OutsideWorkspace(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "change policy I/O: {error}"),
            Self::Json(error) => write!(f, "change policy JSON: {error}"),
            Self::PolicyOutsideWorkspace => write!(f, "policy is outside the workspace"),
            Self::PolicyTooLarge => write!(f, "policy exceeds its byte limit"),
            Self::MalformedPolicy(reason) => write!(f, "malformed change policy: {reason}"),
            Self::UnsupportedPolicy(reason) => write!(f, "unsupported change policy: {reason}"),
            Self::StateOutsideWorkspace => write!(f, "receipt state is outside .cabal"),
            Self::InvalidPath(path) => write!(f, "invalid policy path: {path}"),
            Self::OutsideWorkspace(path) => write!(f, "path escapes workspace: {path}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<io::Error> for PolicyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Loads the fixed opt-in policy location under a workspace.
pub fn load_workspace_policy(workspace_root: &Path) -> Result<PolicyLoad, PolicyError> {
    load_policy(&workspace_root.join(POLICY_RELATIVE_PATH), workspace_root)
}

/// Loads a policy only when its location and every existing ancestor stay in the workspace.
pub fn load_policy(policy_path: &Path, workspace_root: &Path) -> Result<PolicyLoad, PolicyError> {
    let policy_path = resolve_inside_workspace(policy_path, workspace_root)
        .map_err(|_| PolicyError::PolicyOutsideWorkspace)?;
    let raw = match fs::read(policy_path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(PolicyLoad::Disabled),
        Err(error) => return Err(error.into()),
    };
    if raw.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::PolicyTooLarge);
    }
    let wire: WirePolicy = serde_json::from_slice(&raw)
        .map_err(|error| PolicyError::MalformedPolicy(error.to_string()))?;
    if wire.version != 1 {
        return Err(PolicyError::UnsupportedPolicy(format!(
            "version {}",
            wire.version
        )));
    }
    ChangePolicy::from_wire(wire, digest(&raw))
        .map(Box::new)
        .map(PolicyLoad::Active)
}

/// Evaluates the fixed workspace policy. Invalid active configuration fails closed.
pub fn evaluate(workspace_root: &Path, input: ToolInput<'_>) -> Evaluation {
    match load_workspace_policy(workspace_root) {
        Ok(PolicyLoad::Disabled) => disabled_evaluation(),
        Ok(PolicyLoad::Active(policy)) => policy.evaluate(workspace_root, input),
        Err(_) => match input {
            ToolInput::ApplyPatch(_) => {
                denied("invalid_policy", "active change policy is invalid", None)
            }
            ToolInput::Bash(command) if is_builtin_destructive_command(command) => {
                denied("invalid_policy", "active change policy is invalid", None)
            }
            ToolInput::Bash(_) => undecided("invalid_policy", None),
        },
    }
}

impl ChangePolicy {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Evaluates only text and filesystem containment; it never runs the proposed command.
    pub fn evaluate(&self, workspace_root: &Path, input: ToolInput<'_>) -> Evaluation {
        match input {
            ToolInput::ApplyPatch(patch) => match self.evaluate_patch(workspace_root, patch) {
                Ok((decision, code, reason)) => evaluation(decision, code, reason, &self.digest),
                Err((code, reason)) => denied(code, reason, Some(&self.digest)),
            },
            ToolInput::Bash(command) => match self.evaluate_bash(command) {
                Some((decision, code, reason)) => evaluation(decision, code, reason, &self.digest),
                None => undecided("unsupported_command", Some(&self.digest)),
            },
        }
    }

    fn from_wire(wire: WirePolicy, digest: String) -> Result<Self, PolicyError> {
        let paths = wire.paths.unwrap_or_default();
        let rules = wire.rules.unwrap_or_default();
        let limits = wire.limits.unwrap_or_default();
        let commands = wire.commands.unwrap_or_default();
        let mut paths = PathRules::new(paths)?;
        paths.internal_action = rules.internal.unwrap_or(Decision::Ask);
        paths.generated_action = rules.generated.unwrap_or(Decision::Deny);
        Ok(Self {
            digest,
            paths,
            limits: Limits::new(limits)?,
            commands: CommandRules::new(commands)?,
        })
    }

    fn evaluate_patch(
        &self,
        workspace_root: &Path,
        patch: &str,
    ) -> Result<(Decision, &'static str, &'static str), (&'static str, &'static str)> {
        if patch.len() > self.limits.max_patch_bytes {
            return Err(("patch_too_large", "patch exceeds the configured byte limit"));
        }
        let change = parse_patch(patch)?;
        if change.paths.len() > self.limits.max_files {
            return Err(("too_many_files", "patch exceeds the configured file limit"));
        }
        if change.line_changes > self.limits.max_line_changes {
            return Err((
                "too_many_line_changes",
                "patch exceeds the configured line-change limit",
            ));
        }
        let mut decision = Decision::Allow;
        for path in &change.paths {
            validate_lexical_path(path)
                .map_err(|_| ("invalid_path", "patch contains an invalid path"))?;
            ensure_contained_path(workspace_root, path)
                .map_err(|_| ("path_outside_workspace", "patch path escapes the workspace"))?;
            decision = combine(decision, self.paths.decision_for(path)?);
        }
        Ok((decision, decision_code(decision), decision_reason(decision)))
    }

    fn evaluate_bash(&self, command: &str) -> Option<(Decision, &'static str, &'static str)> {
        if is_builtin_destructive_command(command) {
            return Some((
                Decision::Deny,
                decision_code(Decision::Deny),
                decision_reason(Decision::Deny),
            ));
        }
        let argv = parse_bash(command).ok()?;
        let decision = self.commands.decision_for(&argv);
        Some((decision, decision_code(decision), decision_reason(decision)))
    }
}

/// Creates a bounded trusted receipt from an already computed evaluation.
pub fn receipt_for(evaluation: &Evaluation, input: ToolInput<'_>) -> Option<Receipt> {
    let decision = evaluation.decision?;
    Some(Receipt {
        policy_digest: evaluation.policy_digest.clone()?,
        input_kind: match input {
            ToolInput::ApplyPatch(_) => ReceiptKind::ApplyPatch,
            ToolInput::Bash(_) => ReceiptKind::Bash,
        },
        decision: Some(decision),
        code: evaluation.code.clone(),
        input_digest: digest(match input {
            ToolInput::ApplyPatch(text) | ToolInput::Bash(text) => text.as_bytes(),
        }),
        created_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    })
}

/// Atomically writes a receipt under `.cabal/state/change_policy/receipts`.
pub fn write_receipt(workspace_root: &Path, receipt: &Receipt) -> Result<PathBuf, PolicyError> {
    let workspace = fs::canonicalize(workspace_root)?;
    let cabal = workspace.join(".cabal");
    if cabal.exists() && !fs::canonicalize(&cabal)?.starts_with(&workspace) {
        return Err(PolicyError::StateOutsideWorkspace);
    }
    let state = cabal.join("state/change_policy");
    if state.exists() && !fs::canonicalize(&state)?.starts_with(fs::canonicalize(&cabal)?) {
        return Err(PolicyError::StateOutsideWorkspace);
    }
    fs::create_dir_all(&state)?;
    if !fs::canonicalize(&state)?.starts_with(fs::canonicalize(&cabal)?) {
        return Err(PolicyError::StateOutsideWorkspace);
    }
    let _lock = lock_state(&state)?;
    let receipts = state.join("receipts");
    if receipts.exists() && !fs::canonicalize(&receipts)?.starts_with(fs::canonicalize(&state)?) {
        return Err(PolicyError::StateOutsideWorkspace);
    }
    fs::create_dir_all(&receipts)?;
    if !fs::canonicalize(&receipts)?.starts_with(fs::canonicalize(&state)?) {
        return Err(PolicyError::StateOutsideWorkspace);
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .saturating_add(RECEIPT_NONCE.fetch_add(1, Ordering::Relaxed).into());
    let key = digest(
        format!(
            "{}\0{}\0{}\0{nonce}",
            receipt.policy_digest, receipt.input_digest, receipt.code,
        )
        .as_bytes(),
    );
    let path = receipts.join(format!("{key}.json"));
    write_atomic(&path, &serde_json::to_vec(receipt)?)?;
    prune_receipts(&receipts)?;
    Ok(path)
}

fn prune_receipts(receipts: &Path) -> Result<(), PolicyError> {
    let mut entries = fs::read_dir(receipts)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "json")
        })
        .collect::<Vec<_>>();
    if entries.len() <= MAX_RECEIPTS {
        return Ok(());
    }
    entries.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH)
    });
    let remove_count = entries.len() - MAX_RECEIPTS;
    for entry in entries.into_iter().take(remove_count) {
        fs::remove_file(entry.path())?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    version: u32,
    paths: Option<WirePaths>,
    rules: Option<WireRules>,
    limits: Option<WireLimits>,
    commands: Option<WireCommands>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WirePaths {
    allow: Vec<String>,
    deny: Vec<String>,
    internal: Vec<String>,
    generated: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WireRules {
    internal: Option<Decision>,
    generated: Option<Decision>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WireLimits {
    max_patch_bytes: Option<usize>,
    max_files: Option<usize>,
    max_line_changes: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WireCommands {
    allow: Vec<Vec<String>>,
    ask: Vec<Vec<String>>,
    deny: Vec<Vec<String>>,
    destructive: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathRules {
    allow: Vec<String>,
    deny: Vec<String>,
    internal: Vec<String>,
    generated: Vec<String>,
    internal_action: Decision,
    generated_action: Decision,
}

impl PathRules {
    fn new(paths: WirePaths) -> Result<Self, PolicyError> {
        for pattern in [&paths.allow, &paths.deny, &paths.internal, &paths.generated] {
            if pattern.len() > MAX_PATTERNS_PER_CLASS {
                return Err(PolicyError::MalformedPolicy(
                    "too many path patterns".to_owned(),
                ));
            }
            for value in pattern {
                validate_pattern(value)?;
            }
        }
        Ok(Self {
            allow: paths.allow,
            deny: paths.deny,
            internal: paths.internal,
            generated: paths.generated,
            internal_action: Decision::Ask,
            generated_action: Decision::Deny,
        })
    }

    fn decision_for(&self, path: &str) -> Result<Decision, (&'static str, &'static str)> {
        if matches_any(&self.deny, path) {
            return Err(("path_denied", "patch changes a denied path"));
        }
        if !self.allow.is_empty() && !matches_any(&self.allow, path) {
            return Err(("path_not_allowed", "patch path is not in the allow list"));
        }
        let mut decision = Decision::Allow;
        if matches_any(&self.internal, path) {
            decision = combine(decision, self.internal_action);
        }
        if matches_any(&self.generated, path) {
            decision = combine(decision, self.generated_action);
        }
        Ok(decision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Limits {
    max_patch_bytes: usize,
    max_files: usize,
    max_line_changes: usize,
}

impl Limits {
    fn new(wire: WireLimits) -> Result<Self, PolicyError> {
        let limits = Self {
            max_patch_bytes: wire.max_patch_bytes.unwrap_or(65_536),
            max_files: wire.max_files.unwrap_or(32),
            max_line_changes: wire.max_line_changes.unwrap_or(2_000),
        };
        if limits.max_patch_bytes == 0
            || limits.max_patch_bytes > MAX_PATCH_BYTES
            || limits.max_files == 0
            || limits.max_files > MAX_PATCH_FILES
            || limits.max_line_changes == 0
            || limits.max_line_changes > MAX_PATCH_LINE_CHANGES
        {
            return Err(PolicyError::MalformedPolicy(
                "invalid policy limits".to_owned(),
            ));
        }
        Ok(limits)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandRules {
    ask: Vec<Vec<String>>,
    deny: Vec<Vec<String>>,
    destructive: Vec<Vec<String>>,
}

impl CommandRules {
    fn new(wire: WireCommands) -> Result<Self, PolicyError> {
        for commands in [&wire.allow, &wire.ask, &wire.deny, &wire.destructive] {
            if commands.len() > MAX_COMMANDS_PER_CLASS {
                return Err(PolicyError::MalformedPolicy(
                    "too many command rules".to_owned(),
                ));
            }
            for command in commands {
                validate_argv(command)?;
            }
        }
        Ok(Self {
            ask: wire.ask,
            deny: wire.deny,
            destructive: wire.destructive,
        })
    }

    fn decision_for(&self, argv: &[String]) -> Decision {
        if is_builtin_destructive_argv(argv)
            || self.destructive.iter().any(|rule| rule == argv)
            || self.deny.iter().any(|rule| rule == argv)
        {
            Decision::Deny
        } else if self.ask.iter().any(|rule| rule == argv) {
            Decision::Ask
        } else {
            Decision::Allow
        }
    }
}

fn evaluation(decision: Decision, code: &str, reason: &str, digest: &str) -> Evaluation {
    Evaluation {
        state: PolicyState::Active,
        decision: Some(decision),
        code: bound(code, MAX_CODE_BYTES),
        reason: bound(reason, MAX_REASON_BYTES),
        policy_digest: Some(digest.to_owned()),
    }
}

fn denied(code: &str, reason: &str, digest: Option<&str>) -> Evaluation {
    Evaluation {
        state: PolicyState::Active,
        decision: Some(Decision::Deny),
        code: bound(code, MAX_CODE_BYTES),
        reason: bound(reason, MAX_REASON_BYTES),
        policy_digest: digest.map(ToOwned::to_owned),
    }
}

fn disabled_evaluation() -> Evaluation {
    Evaluation {
        state: PolicyState::Disabled,
        decision: None,
        code: "policy_disabled".to_owned(),
        reason: "no change policy is configured".to_owned(),
        policy_digest: None,
    }
}

fn undecided(code: &str, digest: Option<&str>) -> Evaluation {
    Evaluation {
        state: PolicyState::Active,
        decision: None,
        code: bound(code, MAX_CODE_BYTES),
        reason: "change policy made no decision".to_owned(),
        policy_digest: digest.map(ToOwned::to_owned),
    }
}

fn combine(left: Decision, right: Decision) -> Decision {
    match (left, right) {
        (Decision::Deny, _) | (_, Decision::Deny) => Decision::Deny,
        (Decision::Ask, _) | (_, Decision::Ask) => Decision::Ask,
        _ => Decision::Allow,
    }
}

fn decision_code(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allowed",
        Decision::Ask => "approval_required",
        Decision::Deny => "denied_by_policy",
    }
}

fn decision_reason(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "policy allows this change",
        Decision::Ask => "policy requires approval for this change",
        Decision::Deny => "policy denies this change",
    }
}

#[derive(Default)]
struct ParsedPatch {
    paths: BTreeSet<String>,
    line_changes: usize,
}

fn parse_patch(patch: &str) -> Result<ParsedPatch, (&'static str, &'static str)> {
    if patch
        .lines()
        .next()
        .is_some_and(|line| line.trim() == "*** Begin Patch")
    {
        parse_apply_patch(patch)
    } else {
        parse_unified_diff(patch)
    }
}

fn parse_apply_patch(patch: &str) -> Result<ParsedPatch, (&'static str, &'static str)> {
    let mut parsed = ParsedPatch::default();
    let mut current = false;
    let mut ended = false;
    let mut file_header_seen = false;
    let mut environment_id_seen = false;
    let lines = patch.lines().collect::<Vec<_>>();
    let mut in_update = false;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_final_end = index + 1 == lines.len() && trimmed == "*** End Patch";
        let directive = if in_update && !is_final_end {
            line.trim_end()
        } else {
            trimmed
        };
        if trimmed == "*** Begin Patch" {
            if current || ended {
                return Err(("malformed_patch", "patch has an invalid boundary"));
            }
            current = true;
        } else if directive == "*** End Patch" {
            if !current || ended {
                return Err(("malformed_patch", "patch has an invalid boundary"));
            }
            ended = true;
        } else if ended && !trimmed.is_empty() {
            return Err(("malformed_patch", "patch contains data after its boundary"));
        } else if ended {
            continue;
        } else if let Some(environment_id) = directive.strip_prefix("*** Environment ID: ") {
            if !current
                || file_header_seen
                || environment_id_seen
                || environment_id.trim().is_empty()
                || environment_id.len() > 256
            {
                return Err(("malformed_patch", "patch has an invalid environment id"));
            }
            environment_id_seen = true;
        } else if let Some(path) = directive
            .strip_prefix("*** Update File: ")
            .or_else(|| directive.strip_prefix("*** Add File: "))
            .or_else(|| directive.strip_prefix("*** Delete File: "))
        {
            if !current || ended || path.is_empty() {
                return Err(("malformed_patch", "patch has an invalid file header"));
            }
            parsed.paths.insert(normalize_patch_path(path)?);
            file_header_seen = true;
            in_update = directive.starts_with("*** Update File: ");
        } else if let Some(path) = directive.strip_prefix("*** Move to: ") {
            if !current || !file_header_seen || path.is_empty() {
                return Err(("malformed_patch", "patch has an invalid move target"));
            }
            parsed.paths.insert(normalize_patch_path(path)?);
        } else if directive.starts_with("*** ") {
            return Err(("malformed_patch", "patch has an unsupported directive"));
        } else if current
            && !ended
            && (line.starts_with('+') || line.starts_with('-'))
            && !line.starts_with("+++ ")
            && !line.starts_with("--- ")
        {
            parsed.line_changes = parsed.line_changes.saturating_add(1);
        }
    }
    if !current || !ended || parsed.paths.is_empty() {
        return Err(("malformed_patch", "patch has no supported file changes"));
    }
    Ok(parsed)
}

fn parse_unified_diff(patch: &str) -> Result<ParsedPatch, (&'static str, &'static str)> {
    let mut parsed = ParsedPatch::default();
    let mut old: Option<String> = None;
    let mut seen_hunk = false;
    for line in patch.lines() {
        if let Some(path) = line.strip_prefix("--- ") {
            if old.is_some() {
                return Err(("malformed_patch", "patch has unmatched file headers"));
            }
            old = Some(normalize_diff_path(path)?);
        } else if let Some(path) = line.strip_prefix("+++ ") {
            let new = normalize_diff_path(path)?;
            let old = old
                .take()
                .ok_or(("malformed_patch", "patch has unmatched file headers"))?;
            if old != "/dev/null" {
                parsed.paths.insert(old);
            }
            if new != "/dev/null" {
                parsed.paths.insert(new);
            }
        } else if line.starts_with("@@ ") {
            if old.is_some() {
                return Err(("malformed_patch", "patch has an incomplete file pair"));
            }
            seen_hunk = true;
        } else if seen_hunk
            && (line.starts_with('+') || line.starts_with('-'))
            && !line.starts_with("+++ ")
            && !line.starts_with("--- ")
        {
            parsed.line_changes = parsed.line_changes.saturating_add(1);
        }
    }
    if old.is_some() || parsed.paths.is_empty() || !seen_hunk {
        return Err(("malformed_patch", "patch has no supported file changes"));
    }
    Ok(parsed)
}

fn normalize_diff_path(value: &str) -> Result<String, (&'static str, &'static str)> {
    let value = value.split('\t').next().unwrap_or(value);
    if value == "/dev/null" {
        return Ok(value.to_owned());
    }
    let value = value
        .strip_prefix("a/")
        .or_else(|| value.strip_prefix("b/"))
        .unwrap_or(value);
    normalize_patch_path(value)
}

fn normalize_patch_path(path: &str) -> Result<String, (&'static str, &'static str)> {
    validate_lexical_path(path).map_err(|_| ("invalid_path", "patch contains an invalid path"))?;
    Ok(path.replace('\\', "/"))
}

fn parse_bash(command: &str) -> Result<Vec<String>, (&'static str, &'static str)> {
    if command.is_empty()
        || command.len() > MAX_COMMAND_BYTES
        || command.contains(['\n', '\r', '\0'])
    {
        return Err((
            "unsupported_command",
            "command is outside the supported bounded grammar",
        ));
    }
    let mut args = Vec::new();
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else if active == '"' && matches!(ch, '$' | '`') {
                return Err(("unsupported_command", "command uses unsupported expansion"));
            } else if ch == '\\' && active == '"' {
                let escaped = chars
                    .next()
                    .ok_or(("unsupported_command", "command has an unfinished escape"))?;
                if !matches!(escaped, '\\' | '"') {
                    return Err(("unsupported_command", "command uses unsupported quoting"));
                }
                token.push(escaped);
            } else {
                token.push(ch);
            }
        } else if ch.is_ascii_whitespace() {
            if !token.is_empty() {
                args.push(std::mem::take(&mut token));
            }
        } else if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if matches!(
            ch,
            ';' | '|'
                | '&'
                | '<'
                | '>'
                | '`'
                | '$'
                | '('
                | ')'
                | '*'
                | '?'
                | '['
                | ']'
                | '{'
                | '}'
                | '\\'
        ) {
            return Err((
                "unsupported_command",
                "command uses unsupported shell syntax",
            ));
        } else {
            token.push(ch);
        }
    }
    if quote.is_some() {
        return Err(("unsupported_command", "command has an unterminated quote"));
    }
    if !token.is_empty() {
        args.push(token);
    }
    validate_argv(&args).map_err(|_| {
        (
            "unsupported_command",
            "command is outside the supported bounded grammar",
        )
    })?;
    Ok(args)
}

fn is_builtin_destructive_command(command: &str) -> bool {
    if command
        .split_ascii_whitespace()
        .next()
        .is_some_and(is_destructive_program)
    {
        return true;
    }
    parse_bash(command)
        .ok()
        .is_some_and(|argv| is_builtin_destructive_argv(&argv))
}

fn is_builtin_destructive_argv(argv: &[String]) -> bool {
    let Some(program) = argv.first() else {
        return false;
    };
    match program.to_ascii_lowercase().as_str() {
        program if is_destructive_program(program) => true,
        "git" => argv.get(1).is_some_and(|subcommand| {
            subcommand.eq_ignore_ascii_case("restore")
                || (subcommand.eq_ignore_ascii_case("reset")
                    && argv.iter().skip(2).any(|arg| arg == "--hard"))
                || (subcommand.eq_ignore_ascii_case("clean")
                    && argv
                        .iter()
                        .skip(2)
                        .any(|arg| arg.starts_with('-') && arg.contains('f')))
                || (subcommand.eq_ignore_ascii_case("checkout")
                    && argv.iter().skip(2).any(|arg| arg == "--"))
        }),
        _ => false,
    }
}

fn is_destructive_program(program: &str) -> bool {
    matches!(
        program.to_ascii_lowercase().as_str(),
        "rm" | "rmdir" | "rd" | "del" | "erase" | "remove-item"
    )
}

fn validate_argv(argv: &[String]) -> Result<(), PolicyError> {
    if argv.is_empty()
        || argv.len() > MAX_COMMAND_ARGS
        || argv.iter().any(|arg| {
            arg.is_empty() || arg.len() > MAX_COMMAND_ARG_BYTES || arg.contains(['\0', '\n', '\r'])
        })
    {
        return Err(PolicyError::MalformedPolicy(
            "invalid bounded command rule".to_owned(),
        ));
    }
    Ok(())
}

fn validate_pattern(pattern: &str) -> Result<(), PolicyError> {
    if pattern.is_empty() || pattern.len() > 512 || pattern.contains('\0') {
        return Err(PolicyError::MalformedPolicy(
            "invalid path pattern".to_owned(),
        ));
    }
    for segment in pattern.replace('\\', "/").split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains(':') {
            return Err(PolicyError::MalformedPolicy(
                "invalid path pattern".to_owned(),
            ));
        }
    }
    Ok(())
}

fn matches_any(patterns: &[String], path: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| glob_matches(&pattern.replace('\\', "/"), path))
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    fn matches_parts(pattern: &[&str], path: &[&str]) -> bool {
        match pattern.split_first() {
            None => path.is_empty(),
            Some((&"**", rest)) => {
                (0..=path.len()).any(|index| matches_parts(rest, &path[index..]))
            }
            Some((part, rest)) => {
                path.first()
                    .is_some_and(|segment| segment_matches(part, segment))
                    && matches_parts(rest, &path[1..])
            }
        }
    }
    matches_parts(
        &pattern.split('/').collect::<Vec<_>>(),
        &path.split('/').collect::<Vec<_>>(),
    )
}

fn segment_matches(pattern: &str, text: &str) -> bool {
    let (mut p, mut t, mut star, mut checkpoint) = (0, 0, None, 0);
    let pbytes = pattern.as_bytes();
    let tbytes = text.as_bytes();
    while t < tbytes.len() {
        if p < pbytes.len() && (pbytes[p] == tbytes[t]) {
            p += 1;
            t += 1;
        } else if p < pbytes.len() && pbytes[p] == b'*' {
            star = Some(p);
            p += 1;
            checkpoint = t;
        } else if let Some(position) = star {
            p = position + 1;
            checkpoint += 1;
            t = checkpoint;
        } else {
            return false;
        }
    }
    while p < pbytes.len() && pbytes[p] == b'*' {
        p += 1;
    }
    p == pbytes.len()
}

fn validate_lexical_path(path: &str) -> Result<(), PolicyError> {
    if path.is_empty() || path.len() > 4_096 || path.contains('\0') {
        return Err(PolicyError::InvalidPath(path.to_owned()));
    }
    let portable = path.replace('\\', "/");
    if portable.starts_with('/')
        || portable.starts_with("//")
        || portable
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        return Err(PolicyError::InvalidPath(path.to_owned()));
    }
    let native = Path::new(&portable);
    if native.is_absolute()
        || native.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PolicyError::InvalidPath(path.to_owned()));
    }
    Ok(())
}

fn ensure_contained_path(workspace_root: &Path, relative: &str) -> Result<(), PolicyError> {
    let workspace = fs::canonicalize(workspace_root)?;
    let candidate = workspace.join(relative);
    let ancestor = candidate
        .ancestors()
        .find(|path| path.exists())
        .ok_or_else(|| PolicyError::OutsideWorkspace(relative.to_owned()))?;
    if !fs::canonicalize(ancestor)?.starts_with(&workspace) {
        return Err(PolicyError::OutsideWorkspace(relative.to_owned()));
    }
    Ok(())
}

fn resolve_inside_workspace(path: &Path, workspace_root: &Path) -> Result<PathBuf, PolicyError> {
    let workspace = fs::canonicalize(workspace_root)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    let ancestor = candidate
        .ancestors()
        .find(|candidate| candidate.exists())
        .ok_or(PolicyError::PolicyOutsideWorkspace)?;
    if !fs::canonicalize(ancestor)?.starts_with(&workspace) {
        return Err(PolicyError::PolicyOutsideWorkspace);
    }
    Ok(candidate)
}

fn lock_state(state: &Path) -> Result<fs::File, PolicyError> {
    fs::create_dir_all(state)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("state.lock"))?;
    file.lock_exclusive()?;
    Ok(file)
}

fn write_atomic(path: &Path, raw: &[u8]) -> Result<(), PolicyError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("{nonce}.tmp"));
    fs::write(&temporary, raw)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn bound(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests;
