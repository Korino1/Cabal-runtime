//! Deterministic, opt-in evidence checks used by a Stop-hook adapter.
//!
//! This crate deliberately has no hook or transcript API. The caller decides
//! whether a Stop event is recursive, and translates [`Evaluation`] to the
//! host-specific wire response.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::OpenOptions,
    io,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_CONTRACT_BYTES: u64 = 65_536;
pub const MAX_CRITERIA: usize = 64;
pub const MAX_CRITERION_ID_BYTES: usize = 128;
pub const MAX_REASON_BYTES: usize = 2_048;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_INPUT_PATHS_PER_RECEIPT: usize = 64;
pub const MAX_INPUT_FILES_TOTAL: usize = 4_096;

/// A command outcome from a native Cargo execution path, never from model text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl CargoCommand {
    pub fn new(args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: "cargo".to_owned(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pass,
    Block,
    InvalidContract,
    EvidenceUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CriterionStatus {
    Satisfied,
    Missing,
    Failed,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CriterionResult {
    pub id: String,
    pub status: CriterionStatus,
}

/// The deterministic result that a hook adapter can project to its host wire format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Evaluation {
    pub status: GateStatus,
    pub missing_ids: Vec<String>,
    pub reason: String,
    pub criteria: Vec<CriterionResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractLoad {
    Absent,
    Active(CompletionContract),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionContract {
    pub digest: String,
    criteria: Vec<Criterion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Criterion {
    CommandReceipt {
        id: String,
        program: String,
        args: Vec<String>,
        input_paths: Vec<String>,
    },
    FileExists {
        id: String,
        path: String,
    },
    FileAbsent {
        id: String,
        path: String,
    },
    FileSha256 {
        id: String,
        path: String,
        sha256: String,
    },
}

impl Criterion {
    fn id(&self) -> &str {
        match self {
            Self::CommandReceipt { id, .. }
            | Self::FileExists { id, .. }
            | Self::FileAbsent { id, .. }
            | Self::FileSha256 { id, .. } => id,
        }
    }
}

#[derive(Debug)]
pub enum GateError {
    Io(io::Error),
    Json(serde_json::Error),
    ContractOutsideWorkspace,
    ContractTooLarge,
    MalformedContract(String),
    UnsupportedContract(String),
    OutsideWorkspace(String),
    InvalidPath(String),
    PathTooLong,
    TooManyFiles,
    UnsupportedProgram(String),
    NoMatchingCriterion,
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "completion gate I/O: {error}"),
            Self::Json(error) => write!(f, "completion gate JSON: {error}"),
            Self::ContractOutsideWorkspace => write!(f, "contract is outside the workspace"),
            Self::ContractTooLarge => write!(f, "contract exceeds its byte limit"),
            Self::MalformedContract(reason) => write!(f, "malformed completion contract: {reason}"),
            Self::UnsupportedContract(reason) => {
                write!(f, "unsupported completion contract: {reason}")
            }
            Self::OutsideWorkspace(path) => write!(f, "path escapes the workspace: {path}"),
            Self::InvalidPath(path) => write!(f, "invalid workspace-relative path: {path}"),
            Self::PathTooLong => write!(f, "path exceeds its byte limit"),
            Self::TooManyFiles => write!(f, "declared input paths expand to too many files"),
            Self::UnsupportedProgram(program) => {
                write!(f, "unsupported command program: {program}")
            }
            Self::NoMatchingCriterion => {
                write!(f, "command does not match an active receipt criterion")
            }
        }
    }
}

impl std::error::Error for GateError {}

impl From<io::Error> for GateError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for GateError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Loads an opt-in contract. A missing path is not an error and means pass.
pub fn load_contract(
    contract_path: &Path,
    workspace_root: &Path,
) -> Result<ContractLoad, GateError> {
    let contract_path = resolve_contract_location(contract_path, workspace_root)?;
    let raw = match fs::read(contract_path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ContractLoad::Absent),
        Err(error) => return Err(error.into()),
    };
    if raw.len() as u64 > MAX_CONTRACT_BYTES {
        return Err(GateError::ContractTooLarge);
    }
    let wire: WireContract = serde_json::from_slice(&raw)
        .map_err(|error| GateError::MalformedContract(error.to_string()))?;
    if wire.version != 1 {
        return Err(GateError::UnsupportedContract(format!(
            "version {}",
            wire.version
        )));
    }
    let criteria = parse_criteria(wire.criteria)?;
    Ok(ContractLoad::Active(CompletionContract {
        digest: hex_digest(&raw),
        criteria,
    }))
}

/// Evaluates only filesystem predicates and locally recorded native command receipts.
pub fn evaluate(contract_path: &Path, workspace_root: &Path, state_root: &Path) -> Evaluation {
    match evaluate_active(contract_path, workspace_root, state_root) {
        Ok(evaluation) => evaluation,
        Err(error @ GateError::MalformedContract(_))
        | Err(error @ GateError::UnsupportedContract(_)) => invalid_evaluation(error),
        Err(error) => unavailable_evaluation(error),
    }
}

/// Records a trusted native Cargo outcome for an exact command.
///
/// A failure removes the matching success receipt under the same state lock.
pub fn record_cargo_outcome(
    contract_path: &Path,
    workspace_root: &Path,
    state_root: &Path,
    command: &CargoCommand,
    outcome: CargoOutcome,
) -> Result<(), GateError> {
    if command.program != "cargo" {
        return Err(GateError::UnsupportedProgram(command.program.clone()));
    }
    let ContractLoad::Active(contract) = load_contract(contract_path, workspace_root)? else {
        return Err(GateError::NoMatchingCriterion);
    };
    let matching = contract
        .criteria
        .iter()
        .filter_map(|criterion| match criterion {
            Criterion::CommandReceipt {
                id,
                program,
                args,
                input_paths,
            } if program == &command.program && args == &command.args => {
                Some((id.as_str(), input_paths.as_slice()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Err(GateError::NoMatchingCriterion);
    }

    // Build every input digest before changing receipts. A failed command must
    // still invalidate any old receipt even when its current inputs are unreadable.
    let success_digests = if outcome == CargoOutcome::Succeeded {
        Some(
            matching
                .iter()
                .map(|(id, paths)| Ok(((*id).to_owned(), digest_inputs(workspace_root, paths)?)))
                .collect::<Result<Vec<_>, GateError>>()?,
        )
    } else {
        None
    };

    let _lock = lock_state(state_root)?;
    let receipt_dir = state_root.join("receipts");
    fs::create_dir_all(&receipt_dir)?;
    for (id, _) in &matching {
        let path = receipt_dir.join(receipt_filename(&contract.digest, id, command));
        match outcome {
            CargoOutcome::Succeeded => {
                let input_digest = success_digests
                    .as_ref()
                    .and_then(|digests| digests.iter().find(|(digest_id, _)| digest_id == id))
                    .map(|(_, digest)| digest.clone())
                    .expect("matching receipt has a computed digest");
                let receipt = Receipt {
                    contract_digest: contract.digest.clone(),
                    criterion_id: (*id).to_owned(),
                    program: command.program.clone(),
                    args: command.args.clone(),
                    input_digest,
                };
                write_receipt(&path, &receipt)?;
            }
            CargoOutcome::Failed => remove_receipt_if_present(&path)?,
        }
    }
    Ok(())
}

fn evaluate_active(
    contract_path: &Path,
    workspace_root: &Path,
    state_root: &Path,
) -> Result<Evaluation, GateError> {
    let ContractLoad::Active(contract) = load_contract(contract_path, workspace_root)? else {
        return Ok(Evaluation {
            status: GateStatus::Pass,
            missing_ids: Vec::new(),
            reason: String::new(),
            criteria: Vec::new(),
        });
    };
    let _lock = lock_state(state_root)?;
    let mut criteria = contract
        .criteria
        .iter()
        .map(|criterion| {
            evaluate_criterion(criterion, &contract.digest, workspace_root, state_root)
        })
        .collect::<Result<Vec<_>, GateError>>()?;
    criteria.sort_by(|left, right| left.id.cmp(&right.id));
    let missing_ids = criteria
        .iter()
        .filter(|criterion| criterion.status != CriterionStatus::Satisfied)
        .map(|criterion| criterion.id.clone())
        .collect::<Vec<_>>();
    if missing_ids.is_empty() {
        return Ok(Evaluation {
            status: GateStatus::Pass,
            missing_ids,
            reason: String::new(),
            criteria,
        });
    }
    Ok(Evaluation {
        status: GateStatus::Block,
        reason: bounded_reason(&missing_ids),
        missing_ids,
        criteria,
    })
}

fn evaluate_criterion(
    criterion: &Criterion,
    contract_digest: &str,
    workspace_root: &Path,
    state_root: &Path,
) -> Result<CriterionResult, GateError> {
    let status = match criterion {
        Criterion::CommandReceipt {
            id,
            program,
            args,
            input_paths,
        } => {
            let command = CargoCommand {
                program: program.clone(),
                args: args.clone(),
            };
            let receipt_path =
                state_root
                    .join("receipts")
                    .join(receipt_filename(contract_digest, id, &command));
            match read_receipt(&receipt_path)? {
                None => CriterionStatus::Missing,
                Some(receipt)
                    if receipt.contract_digest != contract_digest
                        || receipt.criterion_id != *id
                        || receipt.program != *program
                        || receipt.args != *args =>
                {
                    CriterionStatus::Missing
                }
                Some(receipt)
                    if receipt.input_digest == digest_inputs(workspace_root, input_paths)? =>
                {
                    CriterionStatus::Satisfied
                }
                Some(_) => CriterionStatus::Stale,
            }
        }
        Criterion::FileExists { path, .. } => {
            if matches!(resolve_workspace_candidate(workspace_root, path)?, Some(path) if path.is_file())
            {
                CriterionStatus::Satisfied
            } else {
                CriterionStatus::Failed
            }
        }
        Criterion::FileAbsent { path, .. } => {
            let workspace = fs::canonicalize(workspace_root)?;
            let candidate = workspace.join(path);
            match fs::symlink_metadata(&candidate) {
                Ok(_) => CriterionStatus::Failed,
                Err(error) if error.kind() == io::ErrorKind::NotFound => CriterionStatus::Satisfied,
                Err(error) => return Err(error.into()),
            }
        }
        Criterion::FileSha256 { path, sha256, .. } => {
            match resolve_workspace_candidate(workspace_root, path)? {
                Some(path) if path.is_file() && hex_digest(&read_stable(&path)?) == *sha256 => {
                    CriterionStatus::Satisfied
                }
                _ => CriterionStatus::Failed,
            }
        }
    };
    Ok(CriterionResult {
        id: criterion.id().to_owned(),
        status,
    })
}

fn parse_criteria(values: Vec<serde_json::Value>) -> Result<Vec<Criterion>, GateError> {
    if values.len() > MAX_CRITERIA {
        return Err(GateError::MalformedContract("too many criteria".to_owned()));
    }
    let mut ids = BTreeSet::new();
    let mut criteria = Vec::with_capacity(values.len());
    for value in values {
        let kind = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                GateError::MalformedContract("criterion has no string type".to_owned())
            })?;
        let criterion = match kind {
            "command_receipt" => {
                let wire: CommandReceiptCriterion = serde_json::from_value(value)
                    .map_err(|error| GateError::MalformedContract(error.to_string()))?;
                if wire.program != "cargo" {
                    return Err(GateError::UnsupportedContract(format!(
                        "program {}",
                        wire.program
                    )));
                }
                if wire.input_paths.len() > MAX_INPUT_PATHS_PER_RECEIPT {
                    return Err(GateError::MalformedContract(
                        "too many input paths".to_owned(),
                    ));
                }
                validate_id(&wire.id)?;
                for path in &wire.input_paths {
                    validate_contract_path(path)?;
                }
                Criterion::CommandReceipt {
                    id: wire.id,
                    program: wire.program,
                    args: wire.args,
                    input_paths: wire.input_paths,
                }
            }
            "file_exists" => {
                let wire: FileCriterion = serde_json::from_value(value)
                    .map_err(|error| GateError::MalformedContract(error.to_string()))?;
                validate_id(&wire.id)?;
                validate_contract_path(&wire.path)?;
                Criterion::FileExists {
                    id: wire.id,
                    path: wire.path,
                }
            }
            "file_absent" => {
                let wire: FileCriterion = serde_json::from_value(value)
                    .map_err(|error| GateError::MalformedContract(error.to_string()))?;
                validate_id(&wire.id)?;
                validate_contract_path(&wire.path)?;
                Criterion::FileAbsent {
                    id: wire.id,
                    path: wire.path,
                }
            }
            "file_sha256" => {
                let wire: HashCriterion = serde_json::from_value(value)
                    .map_err(|error| GateError::MalformedContract(error.to_string()))?;
                validate_id(&wire.id)?;
                validate_contract_path(&wire.path)?;
                if !is_sha256(&wire.sha256) {
                    return Err(GateError::MalformedContract("invalid sha256".to_owned()));
                }
                Criterion::FileSha256 {
                    id: wire.id,
                    path: wire.path,
                    sha256: wire.sha256,
                }
            }
            unsupported => {
                return Err(GateError::UnsupportedContract(format!(
                    "criterion type {unsupported}"
                )));
            }
        };
        if !ids.insert(criterion.id().to_owned()) {
            return Err(GateError::MalformedContract(
                "duplicate criterion id".to_owned(),
            ));
        }
        criteria.push(criterion);
    }
    Ok(criteria)
}

fn validate_id(id: &str) -> Result<(), GateError> {
    if id.is_empty()
        || id.len() > MAX_CRITERION_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(GateError::MalformedContract(
            "invalid criterion id".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), GateError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(GateError::PathTooLong);
    }
    let path = Path::new(path);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(GateError::InvalidPath(path.to_string_lossy().into_owned()));
    }
    Ok(())
}

fn validate_contract_path(path: &str) -> Result<(), GateError> {
    validate_relative_path(path).map_err(|error| GateError::MalformedContract(error.to_string()))
}

fn resolve_contract_location(
    contract_path: &Path,
    workspace_root: &Path,
) -> Result<PathBuf, GateError> {
    let workspace = fs::canonicalize(workspace_root)?;
    let candidate = if contract_path.is_absolute() {
        contract_path.to_path_buf()
    } else {
        validate_relative_path(&contract_path.to_string_lossy())?;
        workspace.join(contract_path)
    };
    let existing_ancestor = candidate
        .ancestors()
        .find(|path| path.exists())
        .ok_or(GateError::ContractOutsideWorkspace)?;
    let canonical_ancestor = fs::canonicalize(existing_ancestor)?;
    if !canonical_ancestor.starts_with(&workspace) {
        return Err(GateError::ContractOutsideWorkspace);
    }
    if candidate.exists() {
        let canonical = fs::canonicalize(candidate)?;
        if !canonical.starts_with(&workspace) {
            return Err(GateError::ContractOutsideWorkspace);
        }
        return Ok(canonical);
    }
    Ok(candidate)
}

fn resolve_workspace_candidate(
    workspace_root: &Path,
    raw_path: &str,
) -> Result<Option<PathBuf>, GateError> {
    validate_relative_path(raw_path)?;
    let workspace = fs::canonicalize(workspace_root)?;
    let candidate = workspace.join(raw_path);
    if candidate.exists() {
        let canonical = fs::canonicalize(&candidate)?;
        if !canonical.starts_with(&workspace) {
            return Err(GateError::OutsideWorkspace(raw_path.to_owned()));
        }
        Ok(Some(canonical))
    } else {
        Ok(None)
    }
}

fn resolve_existing_workspace_path(
    workspace_root: &Path,
    raw_path: &str,
) -> Result<PathBuf, GateError> {
    resolve_workspace_candidate(workspace_root, raw_path)?
        .ok_or_else(|| GateError::Io(io::Error::from(io::ErrorKind::NotFound)))
}

fn digest_inputs(workspace_root: &Path, input_paths: &[String]) -> Result<String, GateError> {
    let workspace = fs::canonicalize(workspace_root)?;
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for raw_path in input_paths {
        let path = resolve_existing_workspace_path(&workspace, raw_path)?;
        collect_files(&workspace, &path, &mut files, &mut directories)?;
    }
    let mut digest = Sha256::new();
    for path in files {
        let relative = path
            .strip_prefix(&workspace)
            .map_err(|_| GateError::OutsideWorkspace(path.to_string_lossy().into_owned()))?
            .to_string_lossy()
            .replace('\\', "/");
        let raw = read_stable(&path)?;
        digest.update(b"file\0");
        digest.update(relative.as_bytes());
        digest.update(b"\0");
        digest.update(raw);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn collect_files(
    workspace: &Path,
    path: &Path,
    files: &mut BTreeSet<PathBuf>,
    directories: &mut BTreeSet<PathBuf>,
) -> Result<(), GateError> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(workspace) {
        return Err(GateError::OutsideWorkspace(
            path.to_string_lossy().into_owned(),
        ));
    }
    let metadata = fs::metadata(&canonical)?;
    if metadata.is_file() {
        files.insert(canonical);
        if files.len() > MAX_INPUT_FILES_TOTAL {
            return Err(GateError::TooManyFiles);
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(GateError::InvalidPath(path.to_string_lossy().into_owned()));
    }
    if !directories.insert(canonical.clone()) {
        return Ok(());
    }
    if directories.len() > MAX_INPUT_FILES_TOTAL {
        return Err(GateError::TooManyFiles);
    }
    for entry in fs::read_dir(canonical)? {
        collect_files(workspace, &entry?.path(), files, directories)?;
    }
    Ok(())
}

fn read_stable(path: &Path) -> Result<Vec<u8>, GateError> {
    for _ in 0..3 {
        let first = fs::read(path)?;
        let second = fs::read(path)?;
        if first == second {
            return Ok(first);
        }
    }
    Err(GateError::Io(io::Error::other(
        "file changed during digest",
    )))
}

fn lock_state(state_root: &Path) -> Result<fs::File, GateError> {
    fs::create_dir_all(state_root)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state_root.join("state.lock"))?;
    lock.lock_exclusive()?;
    Ok(lock)
}

fn receipt_filename(contract_digest: &str, id: &str, command: &CargoCommand) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contract_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(id.as_bytes());
    hasher.update(b"\0");
    hasher.update(command.program.as_bytes());
    hasher.update(b"\0");
    for argument in &command.args {
        hasher.update(argument.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}.json", hasher.finalize())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContract {
    version: u64,
    criteria: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandReceiptCriterion {
    id: String,
    #[serde(rename = "type")]
    _kind: String,
    program: String,
    args: Vec<String>,
    input_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCriterion {
    id: String,
    #[serde(rename = "type")]
    _kind: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashCriterion {
    id: String,
    #[serde(rename = "type")]
    _kind: String,
    path: String,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
struct Receipt {
    contract_digest: String,
    criterion_id: String,
    program: String,
    args: Vec<String>,
    input_digest: String,
}

fn read_receipt(path: &Path) -> Result<Option<Receipt>, GateError> {
    match fs::read(path) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_receipt(path: &Path, receipt: &Receipt) -> Result<(), GateError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("{nonce}.tmp"));
    fs::write(&temporary, serde_json::to_vec(receipt)?)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn remove_receipt_if_present(path: &Path) -> Result<(), GateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn invalid_evaluation(error: GateError) -> Evaluation {
    Evaluation {
        status: GateStatus::InvalidContract,
        missing_ids: Vec::new(),
        reason: bounded_text(&format!("invalid_contract: {error}")),
        criteria: Vec::new(),
    }
}

fn unavailable_evaluation(error: GateError) -> Evaluation {
    Evaluation {
        status: GateStatus::EvidenceUnavailable,
        missing_ids: Vec::new(),
        reason: bounded_text(&format!("evidence_unavailable: {error}")),
        criteria: Vec::new(),
    }
}

fn bounded_reason(ids: &[String]) -> String {
    bounded_text(&format!("missing: {}", ids.join(",")))
}

fn bounded_text(text: &str) -> String {
    if text.len() <= MAX_REASON_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_REASON_BYTES.saturating_sub(3);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn hex_digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests;
