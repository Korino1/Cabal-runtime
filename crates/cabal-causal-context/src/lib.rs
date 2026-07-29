//! Fail-closed, private projection of one exact contextual `rg` search.
//!
//! The public surface is intentionally small: a hook creates a [`Gateway`],
//! registers a lifecycle frame, prepares an opaque request, and then executes
//! that request. Only a strictly smaller lossless projection is returned.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use cap_std::{ambient_authority, fs::Dir};
use fs2::FileExt;
use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum accepted identifier bytes, excluding optional quotes.
pub const MAX_IDENTIFIER_BYTES: usize = 128;
/// Maximum serialized private observer frame.
pub const MAX_OBSERVER_FRAME_BYTES: usize = 4_096;
/// Maximum serialized private request.
pub const MAX_PRIVATE_REQUEST_BYTES: usize = 16_384;
/// Combined bounded stdout and stderr capture size.
pub const MAX_RAW_SEARCH_BYTES: usize = 8 * 1024 * 1024;
/// Maximum model-visible projection size.
pub const MAX_MODEL_PROJECTION_BYTES: usize = 64 * 1024;
/// Maximum retained raw match and context records.
pub const MAX_RAW_MATCH_LOCATIONS: usize = 4_096;
/// Logical observer-frame lifetime.
pub const FRAME_TTL_SECONDS: u64 = 24 * 60 * 60;
/// Request lifetime.
pub const REQUEST_TTL_SECONDS: u64 = 60;
/// Orphan raw-capture lifetime.
pub const ORPHAN_RAW_TTL_SECONDS: u64 = 600;
/// Maximum private state owned by this crate.
pub const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum duration for the private ripgrep execution.
pub const EXECUTOR_TIMEOUT: Duration = Duration::from_secs(30);

const STATE_DIRECTORY: &str = "cabal-runtime/causal-context";
const STATE_LOCK: &str = "state.lock";
const FRAME_DIRECTORY: &str = "frames";
const REQUEST_DIRECTORY: &str = "requests";
const RAW_DIRECTORY: &str = "raw";
const VERIFY_DIRECTORY: &str = "verify";
const REQUEST_VERSION: u32 = 1;
const FRAME_VERSION: u32 = 1;
const MAX_ID_INPUT_BYTES: usize = 4_096;

/// A capability-bound M-010 state owner.
#[derive(Clone, Debug)]
pub struct Gateway {
    workspace: PathBuf,
    git_service_root: PathBuf,
    state_root: PathBuf,
}

/// Opaque token returned to a hook after a request was written successfully.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRequest {
    token: String,
    search: ExactSearch,
}

impl PreparedRequest {
    /// The CSPRNG-generated lower-case 64-hex token for the executor command.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The exact original search used only by the generated fail-open wrapper.
    pub fn search(&self) -> &ExactSearch {
        &self.search
    }
}

/// The exact supported search, available only to a raw-replay caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactSearch {
    identifier: String,
}

impl ExactSearch {
    /// Returns the unquoted ASCII Rust identifier.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Reconstructs the only accepted command wire form.
    pub fn command(&self) -> String {
        format!("rg -n -C 8 -- {} .", self.identifier)
    }

    /// Returns the direct, shell-free argv for ripgrep.
    pub fn argv(&self) -> [&str; 6] {
        ["-n", "-C", "8", "--", &self.identifier, "."]
    }
}

/// Why an executor caller must run the exact original search instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayReason {
    RequestExpired,
    SessionStale,
    RevisionStale,
    CaptureOverflow,
    CaptureTimedOut,
    RipgrepError,
    RipgrepExit,
    RawParse,
    SourceIdentityStale,
    Integrity,
    ProjectionTooLarge,
    ProjectionNotSmaller,
    ExecutionError,
}

/// Result returned by [`Gateway::execute_request`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The only success path. The executor should write `text` and exit zero.
    Projection { text: String, exit_code: i32 },
    /// Run `search` directly from the original canonical workspace with inherited streams.
    RawReplay {
        search: ExactSearch,
        reason: ReplayReason,
        /// Private rg exit status when capture completed. Values 0, 1, and 2
        /// are retained exactly rather than being normalized.
        captured_exit_code: Option<i32>,
    },
    /// The opaque request could not safely yield an exact replay specification.
    /// It was deleted before returning this result.
    Rejected { reason: RequestRejection },
}

/// A request-rejection reason that never contains request, workspace, or prompt data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestRejection {
    InvalidToken,
    Missing,
    Oversized,
    Malformed,
    Incompatible,
    StateUnavailable,
}

/// Number of private state artifacts removed by [`Gateway::cleanup`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    pub expired_frames: u64,
    pub expired_requests: u64,
    pub orphan_raw_files: u64,
    pub orphan_verification_entries: u64,
    pub malformed_files: u64,
}

/// Errors before a hook rewrites its original command.
#[derive(Debug)]
pub enum GatewayError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidWorkspace,
    GitServiceMismatch,
    UnsafeStatePath,
    InvalidInput(&'static str),
    Clock,
    StateLimit,
    Randomness,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "causal context I/O: {error}"),
            Self::Json(error) => write!(formatter, "causal context JSON: {error}"),
            Self::InvalidWorkspace => write!(formatter, "workspace is not a Git worktree root"),
            Self::GitServiceMismatch => {
                write!(formatter, "Git service root does not match workspace")
            }
            Self::UnsafeStatePath => write!(formatter, "private state path is unsafe"),
            Self::InvalidInput(message) => {
                write!(formatter, "invalid causal context input: {message}")
            }
            Self::Clock => write!(formatter, "system clock is unavailable"),
            Self::StateLimit => write!(formatter, "private state exceeds its byte bound"),
            Self::Randomness => write!(formatter, "CSPRNG request token generation failed"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<io::Error> for GatewayError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for GatewayError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl Gateway {
    /// Opens state only when `workspace_root` is the canonical Git worktree root
    /// and `git_service_root` resolves to that worktree's Git service directory.
    pub fn open(workspace_root: &Path, git_service_root: &Path) -> Result<Self, GatewayError> {
        let workspace =
            fs::canonicalize(workspace_root).map_err(|_| GatewayError::InvalidWorkspace)?;
        if !workspace.is_dir() {
            return Err(GatewayError::InvalidWorkspace);
        }
        let discovered_git =
            resolve_git_service_root(&workspace).ok_or(GatewayError::InvalidWorkspace)?;
        let supplied_git =
            fs::canonicalize(git_service_root).map_err(|_| GatewayError::GitServiceMismatch)?;
        if discovered_git != supplied_git || !supplied_git.is_dir() {
            return Err(GatewayError::GitServiceMismatch);
        }
        let state_root = supplied_git.join(STATE_DIRECTORY);
        let gateway = Self {
            workspace,
            git_service_root: supplied_git.clone(),
            state_root,
        };
        gateway.open_state_dir()?;
        Ok(gateway)
    }

    /// Canonical workspace root used for direct raw replay.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Canonical Git service root supplied to [`Gateway::open`].
    pub fn git_service_root(&self) -> &Path {
        &self.git_service_root
    }

    /// Silently persists the current private lifecycle frame.
    ///
    /// The caller should ignore this error for a UserPromptSubmit fail-open path.
    pub fn register_frame(
        &self,
        session_id: &str,
        turn_id: Option<&str>,
    ) -> Result<(), GatewayError> {
        let now = unix_seconds()?;
        self.with_lock(|| {
            self.cleanup_locked(now)?;
            let session_digest = digest_id(session_id)?;
            let turn_digest = turn_id.map(digest_id).transpose()?;
            let frame = ObserverFrameLite {
                version: FRAME_VERSION,
                session_digest: session_digest.clone(),
                turn_digest,
                git_head: read_git_head(&self.workspace, &self.git_service_root),
                registered_at: now,
                expires_at: now.saturating_add(FRAME_TTL_SECONDS),
            };
            let raw = serde_json::to_vec(&frame)?;
            if raw.len() > MAX_OBSERVER_FRAME_BYTES {
                return Err(GatewayError::InvalidInput(
                    "observer frame exceeds its bound",
                ));
            }
            // The atomic temporary coexists with the previous frame until
            // replacement, so reserve the complete serialized size.
            self.ensure_state_capacity(raw.len() as u64)?;
            self.write_atomic(&self.frame_path(&session_digest), &raw)
        })
    }

    /// Creates a one-use private request for the exact supported command.
    ///
    /// `Ok(None)` means the command is unsupported and the hook must not emit a
    /// decision. Any `Err` likewise happens before rewrite, so the original
    /// Codex execution remains authoritative.
    pub fn prepare_request(
        &self,
        session_id: &str,
        cwd: &Path,
        command: &str,
    ) -> Result<Option<PreparedRequest>, GatewayError> {
        let Some(search) = parse_exact_search(command) else {
            return Ok(None);
        };
        let canonical_cwd = fs::canonicalize(cwd).map_err(|_| GatewayError::InvalidWorkspace)?;
        if canonical_cwd != self.workspace {
            return Ok(None);
        }
        let session_digest = digest_id(session_id)?;
        let now = unix_seconds()?;
        self.with_lock(|| {
            self.cleanup_locked(now)?;
            let frame = self
                .read_frame(&session_digest)?
                .ok_or(GatewayError::InvalidInput(
                    "active observer frame is missing",
                ))?;
            if frame.expires_at <= now || frame.version != FRAME_VERSION {
                let _ = remove_if_file(&self.frame_path(&session_digest));
                return Err(GatewayError::InvalidInput("active observer frame is stale"));
            }
            let current_head = read_git_head(&self.workspace, &self.git_service_root);
            if current_head != frame.git_head {
                return Err(GatewayError::InvalidInput(
                    "Git revision changed after frame registration",
                ));
            }

            let request = CausalContextRequest {
                version: REQUEST_VERSION,
                session_digest,
                turn_digest: frame.turn_digest,
                frame_registered_at: frame.registered_at,
                git_head: current_head,
                identifier: search.identifier,
                created_at: now,
                expires_at: now.saturating_add(REQUEST_TTL_SECONDS),
            };
            let raw = serde_json::to_vec(&request)?;
            if raw.len() > MAX_PRIVATE_REQUEST_BYTES {
                return Err(GatewayError::InvalidInput(
                    "causal context request exceeds its bound",
                ));
            }
            self.ensure_state_capacity(raw.len() as u64)?;
            for _ in 0..4 {
                let token = random_token()?;
                match create_new_file(&self.request_path(&token), &raw) {
                    Ok(()) => {
                        return Ok(Some(PreparedRequest {
                            token,
                            search: ExactSearch {
                                identifier: request.identifier.clone(),
                            },
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(GatewayError::Randomness)
        })
    }

    /// Consumes one request, invokes exact shell-free `rg`, and returns either a
    /// strictly smaller projection or an exact raw replay requirement.
    pub fn execute_request(&self, token: &str) -> Outcome {
        if !is_request_token(token) {
            return Outcome::Rejected {
                reason: RequestRejection::InvalidToken,
            };
        }
        let now = match unix_seconds() {
            Ok(value) => value,
            Err(_) => {
                return Outcome::Rejected {
                    reason: RequestRejection::StateUnavailable,
                };
            }
        };
        let request = match self.with_lock(|| self.consume_request_locked(token, now)) {
            Ok(ConsumedRequest::Request(request)) => request,
            Ok(ConsumedRequest::Rejected(reason)) => return Outcome::Rejected { reason },
            Err(_) => {
                return Outcome::Rejected {
                    reason: RequestRejection::StateUnavailable,
                };
            }
        };
        let search = ExactSearch {
            identifier: request.identifier.clone(),
        };
        if request.expires_at <= now {
            return replay(search, ReplayReason::RequestExpired, None);
        }
        if request.version != REQUEST_VERSION || !is_identifier(&request.identifier) {
            return Outcome::Rejected {
                reason: RequestRejection::Incompatible,
            };
        }
        match self.frame_is_current(&request, now) {
            Ok(true) => {}
            Ok(false) => return replay(search, ReplayReason::SessionStale, None),
            Err(_) => return replay(search, ReplayReason::ExecutionError, None),
        }
        if read_git_head(&self.workspace, &self.git_service_root) != request.git_head {
            return replay(search, ReplayReason::RevisionStale, None);
        }

        let capture = match self.run_rg(token, &search) {
            Ok(capture) => capture,
            Err(_) => return replay(search, ReplayReason::ExecutionError, None),
        };
        let captured_exit_code = capture.exit_code;
        if let Some(reason) = capture_replay_reason(&capture) {
            return replay(search, reason, captured_exit_code);
        }

        let records = match parse_raw_records(&capture.stdout, &self.workspace) {
            Ok(records) => records,
            Err(_) => return replay(search, ReplayReason::RawParse, captured_exit_code),
        };
        let packet = InternalContextPacketV1 {
            query: search.identifier.clone(),
            records,
            raw_bytes: capture.stdout.len(),
        };
        let text = match render_projection(&packet) {
            Ok(text) => text,
            Err(ProjectionError::TooLarge) => {
                return replay(search, ReplayReason::ProjectionTooLarge, captured_exit_code);
            }
            Err(ProjectionError::Invalid) => {
                return replay(search, ReplayReason::Integrity, captured_exit_code);
            }
        };
        if text.len() >= capture.stdout.len() {
            return replay(
                search,
                ReplayReason::ProjectionNotSmaller,
                captured_exit_code,
            );
        }
        Outcome::Projection { text, exit_code: 0 }
    }

    /// Removes expired frames and requests plus orphan private raw captures.
    pub fn cleanup(&self) -> Result<CleanupReport, GatewayError> {
        let now = unix_seconds()?;
        self.with_lock(|| self.cleanup_locked(now))
    }

    fn frame_is_current(
        &self,
        request: &CausalContextRequest,
        now: u64,
    ) -> Result<bool, GatewayError> {
        self.with_lock(|| {
            self.cleanup_locked(now)?;
            let Some(frame) = self.read_frame(&request.session_digest)? else {
                return Ok(false);
            };
            Ok(frame.version == FRAME_VERSION
                && frame.expires_at > now
                && frame.registered_at == request.frame_registered_at
                && frame.turn_digest == request.turn_digest
                && frame.git_head == request.git_head)
        })
    }

    fn run_rg(&self, token: &str, search: &ExactSearch) -> Result<Capture, GatewayError> {
        self.with_lock(|| {
            let now = unix_seconds()?;
            self.cleanup_locked(now)?;
            self.ensure_state_capacity(MAX_RAW_SEARCH_BYTES as u64)?;
            let raw_dir = self.open_child_dir(RAW_DIRECTORY)?;
            let stdout_path = raw_dir.join(format!("{token}.stdout"));
            let stderr_path = raw_dir.join(format!("{token}.stderr"));
            let result = run_bounded_process(&self.workspace, search, &stdout_path, &stderr_path);
            let stdout = fs::read(&stdout_path).unwrap_or_default();
            let stderr = fs::read(&stderr_path).unwrap_or_default();
            let _ = remove_if_file(&stdout_path);
            let _ = remove_if_file(&stderr_path);
            result.map(|status| Capture {
                stdout,
                stderr,
                exit_code: status.exit_code,
                overflowed: status.overflowed,
                timed_out: status.timed_out,
            })
        })
    }

    fn consume_request_locked(
        &self,
        token: &str,
        now: u64,
    ) -> Result<ConsumedRequest, GatewayError> {
        self.cleanup_locked_except(now, Some(token))?;
        let path = self.request_path(token);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ConsumedRequest::Rejected(RequestRejection::Missing));
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_PRIVATE_REQUEST_BYTES as u64
        {
            let _ = remove_if_file(&path);
            return Ok(ConsumedRequest::Rejected(RequestRejection::Oversized));
        }
        let mut raw = Vec::new();
        File::open(&path)?
            .take(MAX_PRIVATE_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut raw)?;
        let _ = remove_if_file(&path);
        if raw.len() > MAX_PRIVATE_REQUEST_BYTES {
            return Ok(ConsumedRequest::Rejected(RequestRejection::Oversized));
        }
        match serde_json::from_slice(&raw) {
            Ok(request) => Ok(ConsumedRequest::Request(request)),
            Err(_) => Ok(ConsumedRequest::Rejected(RequestRejection::Malformed)),
        }
    }

    fn read_frame(&self, session_digest: &str) -> Result<Option<ObserverFrameLite>, GatewayError> {
        let path = self.frame_path(session_digest);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_OBSERVER_FRAME_BYTES as u64
        {
            let _ = remove_if_file(&path);
            return Ok(None);
        }
        let raw = fs::read(path)?;
        match serde_json::from_slice(&raw) {
            Ok(frame) => Ok(Some(frame)),
            Err(_) => Ok(None),
        }
    }

    fn cleanup_locked(&self, now: u64) -> Result<CleanupReport, GatewayError> {
        self.cleanup_locked_except(now, None)
    }

    fn cleanup_locked_except(
        &self,
        now: u64,
        excluded_request: Option<&str>,
    ) -> Result<CleanupReport, GatewayError> {
        self.open_state_dir()?;
        let excluded_request_file = excluded_request.map(|token| format!("{token}.json"));
        let mut report = CleanupReport::default();
        report.expired_frames = self.cleanup_serialized_directory(
            FRAME_DIRECTORY,
            MAX_OBSERVER_FRAME_BYTES,
            now,
            None,
            |raw| {
                serde_json::from_slice::<ObserverFrameLite>(raw)
                    .ok()
                    .is_none_or(|frame| frame.version != FRAME_VERSION || frame.expires_at <= now)
            },
            &mut report.malformed_files,
        )?;
        report.expired_requests = self.cleanup_serialized_directory(
            REQUEST_DIRECTORY,
            MAX_PRIVATE_REQUEST_BYTES,
            now,
            excluded_request_file.as_deref().map(OsStr::new),
            |raw| {
                serde_json::from_slice::<CausalContextRequest>(raw)
                    .ok()
                    .is_none_or(|request| {
                        request.version != REQUEST_VERSION || request.expires_at <= now
                    })
            },
            &mut report.malformed_files,
        )?;
        let raw_dir = self.open_child_dir(RAW_DIRECTORY)?;
        for entry in fs::read_dir(raw_dir)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            let expired = metadata.file_type().is_symlink()
                || !metadata.is_file()
                || modified_seconds(&metadata)
                    .is_none_or(|modified| now.saturating_sub(modified) >= ORPHAN_RAW_TTL_SECONDS);
            if expired {
                let _ = remove_if_file(&entry.path());
                report.orphan_raw_files += 1;
            }
        }
        let verify_dir = self.open_child_dir(VERIFY_DIRECTORY)?;
        for entry in fs::read_dir(&verify_dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(GatewayError::UnsafeStatePath);
            } else if metadata.is_dir() {
                let canonical = fs::canonicalize(&path)?;
                if !canonical.starts_with(&verify_dir) {
                    return Err(GatewayError::UnsafeStatePath);
                }
                fs::remove_dir_all(canonical)?;
            } else if metadata.is_file() {
                remove_if_file(&path)?;
            } else {
                return Err(GatewayError::UnsafeStatePath);
            }
            report.orphan_verification_entries += 1;
        }
        if self.state_usage()? > MAX_STATE_BYTES {
            return Err(GatewayError::StateLimit);
        }
        Ok(report)
    }

    fn cleanup_serialized_directory<F>(
        &self,
        directory: &str,
        max_bytes: usize,
        _now: u64,
        excluded_file: Option<&OsStr>,
        expired: F,
        malformed: &mut u64,
    ) -> Result<u64, GatewayError>
    where
        F: Fn(&[u8]) -> bool,
    {
        let path = self.open_child_dir(directory)?;
        let mut removed = 0;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if excluded_file.is_some_and(|name| entry.file_name() == name) {
                continue;
            }
            let entry_path = entry.path();
            let valid_name = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .is_some_and(is_request_token);
            if !valid_name {
                let _ = remove_if_file(&entry_path);
                *malformed += 1;
                continue;
            }
            let metadata = fs::symlink_metadata(&entry_path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > max_bytes as u64
            {
                let _ = remove_if_file(&entry_path);
                *malformed += 1;
                continue;
            }
            let raw = fs::read(&entry_path)?;
            if expired(&raw) {
                let malformed_entry = serde_json::from_slice::<serde_json::Value>(&raw).is_err();
                let _ = remove_if_file(&entry_path);
                removed += 1;
                if malformed_entry {
                    *malformed += 1;
                }
            }
        }
        Ok(removed)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, GatewayError>,
    ) -> Result<T, GatewayError> {
        self.open_state_dir()?;
        let lock_path = self.state_root.join(STATE_LOCK);
        reject_symlink_file(&lock_path)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        set_owner_only_create_mode(&mut options);
        let lock = options.open(&lock_path)?;
        set_owner_only_file(&lock_path)?;
        lock.lock_exclusive()?;
        let result = operation();
        let _ = FileExt::unlock(&lock);
        result
    }

    fn open_state_dir(&self) -> Result<(), GatewayError> {
        let relative = Path::new(STATE_DIRECTORY);
        ensure_relative_path(relative)?;
        reject_symlink_components(&self.git_service_root, relative)?;
        let git_dir = Dir::open_ambient_dir(&self.git_service_root, ambient_authority())?;
        git_dir.create_dir_all(relative)?;
        let canonical = fs::canonicalize(&self.state_root)?;
        if !canonical.starts_with(&self.git_service_root) || canonical != self.state_root {
            return Err(GatewayError::UnsafeStatePath);
        }
        set_owner_only_directory(&self.state_root)?;
        for child in [
            FRAME_DIRECTORY,
            REQUEST_DIRECTORY,
            RAW_DIRECTORY,
            VERIFY_DIRECTORY,
        ] {
            self.open_child_dir(child)?;
        }
        Ok(())
    }

    fn open_child_dir(&self, name: &str) -> Result<PathBuf, GatewayError> {
        let path = self.state_root.join(name);
        reject_symlink_components(&self.state_root, Path::new(name))?;
        if !path.exists() {
            fs::create_dir(&path)?;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(GatewayError::UnsafeStatePath);
        }
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&self.state_root) || canonical != path {
            return Err(GatewayError::UnsafeStatePath);
        }
        set_owner_only_directory(&path)?;
        Ok(path)
    }

    fn ensure_state_capacity(&self, additional: u64) -> Result<(), GatewayError> {
        if self.state_usage()?.saturating_add(additional) > MAX_STATE_BYTES {
            return Err(GatewayError::StateLimit);
        }
        Ok(())
    }

    fn state_usage(&self) -> Result<u64, GatewayError> {
        state_usage(&self.state_root)
    }

    fn frame_path(&self, session_digest: &str) -> PathBuf {
        self.state_root
            .join(FRAME_DIRECTORY)
            .join(format!("{session_digest}.json"))
    }

    fn request_path(&self, token: &str) -> PathBuf {
        self.state_root
            .join(REQUEST_DIRECTORY)
            .join(format!("{token}.json"))
    }

    fn write_atomic(&self, destination: &Path, raw: &[u8]) -> Result<(), GatewayError> {
        let parent = destination.parent().ok_or(GatewayError::UnsafeStatePath)?;
        let token = random_token()?;
        let temporary = parent.join(format!(".{token}.tmp"));
        create_new_file(&temporary, raw)?;
        if let Err(error) = fs::rename(&temporary, destination) {
            // The state lock serializes writers. Windows may reject replacing an
            // existing destination, so retry once after removal while locked.
            if error.kind() != io::ErrorKind::AlreadyExists {
                let _ = remove_if_file(&temporary);
                return Err(error.into());
            }
            remove_if_file(destination)?;
            if let Err(error) = fs::rename(&temporary, destination) {
                let _ = remove_if_file(&temporary);
                return Err(error.into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ObserverFrameLite {
    version: u32,
    session_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn_digest: Option<String>,
    git_head: GitHead,
    registered_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum GitHead {
    Commit { value: String },
    Unborn,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CausalContextRequest {
    version: u32,
    session_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn_digest: Option<String>,
    frame_registered_at: u64,
    git_head: GitHead,
    identifier: String,
    created_at: u64,
    expires_at: u64,
}

enum ConsumedRequest {
    Request(CausalContextRequest),
    Rejected(RequestRejection),
}

#[derive(Clone, Debug)]
struct RawRecord {
    display_path: String,
    line: u64,
    kind: RecordKind,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordKind {
    Match,
    Context,
}

struct InternalContextPacketV1 {
    query: String,
    records: Vec<RawRecord>,
    raw_bytes: usize,
}

#[derive(Debug)]
enum ProjectionError {
    TooLarge,
    Invalid,
}

struct Capture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    overflowed: bool,
    timed_out: bool,
}

struct ProcessStatus {
    exit_code: Option<i32>,
    overflowed: bool,
    timed_out: bool,
}

fn replay(search: ExactSearch, reason: ReplayReason, captured_exit_code: Option<i32>) -> Outcome {
    Outcome::RawReplay {
        search,
        reason,
        captured_exit_code,
    }
}

fn capture_replay_reason(capture: &Capture) -> Option<ReplayReason> {
    if capture.overflowed {
        Some(ReplayReason::CaptureOverflow)
    } else if capture.timed_out {
        Some(ReplayReason::CaptureTimedOut)
    } else if !capture.stderr.is_empty() {
        Some(ReplayReason::RipgrepError)
    } else if capture.exit_code != Some(0) {
        Some(ReplayReason::RipgrepExit)
    } else {
        None
    }
}

fn parse_exact_search(command: &str) -> Option<ExactSearch> {
    if !command.is_ascii()
        || command
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b'\t'))
    {
        return None;
    }
    let prefix = "rg -n -C 8 -- ";
    let suffix = " .";
    let identifier = command.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if identifier.is_empty() || identifier.contains(' ') {
        return None;
    }
    let identifier = match (identifier.as_bytes().first(), identifier.as_bytes().last()) {
        (Some(b'\''), Some(b'\'')) | (Some(b'\"'), Some(b'\"')) if identifier.len() >= 2 => {
            &identifier[1..identifier.len() - 1]
        }
        (Some(b'\'' | b'\"'), _) | (_, Some(b'\'' | b'\"')) => return None,
        _ => identifier,
    };
    is_identifier(identifier).then(|| ExactSearch {
        identifier: identifier.to_owned(),
    })
}

fn is_identifier(identifier: &str) -> bool {
    let bytes = identifier.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn digest_id(value: &str) -> Result<String, GatewayError> {
    if value.is_empty() || value.len() > MAX_ID_INPUT_BYTES {
        return Err(GatewayError::InvalidInput(
            "session or turn identifier is out of bounds",
        ));
    }
    Ok(format!("{:x}", Sha256::digest(value.as_bytes())))
}

fn random_token() -> Result<String, GatewayError> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes).map_err(|_| GatewayError::Randomness)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn is_request_token(token: &str) -> bool {
    token.len() == 64
        && token.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn unix_seconds() -> Result<u64, GatewayError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayError::Clock)
        .map(|duration| duration.as_secs())
}

fn resolve_git_service_root(workspace: &Path) -> Option<PathBuf> {
    let dot_git = workspace.join(".git");
    if dot_git.is_dir() {
        return fs::canonicalize(dot_git).ok();
    }
    let raw = fs::read_to_string(dot_git).ok()?;
    let location = raw.strip_prefix("gitdir: ")?.trim();
    let path = PathBuf::from(location);
    fs::canonicalize(if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    })
    .ok()
}

fn read_git_head(workspace: &Path, git_service_root: &Path) -> GitHead {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(workspace)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() && output.stdout.len() <= 256 => {
            parse_commit(std::str::from_utf8(&output.stdout).ok())
        }
        Ok(_) => match fs::read_to_string(git_service_root.join("HEAD")) {
            Ok(head) if head.trim().starts_with("ref: refs/") => GitHead::Unborn,
            _ => GitHead::Unavailable,
        },
        Err(_) => GitHead::Unavailable,
    }
}

fn parse_commit(value: Option<&str>) -> GitHead {
    let Some(value) = value.map(str::trim) else {
        return GitHead::Unavailable;
    };
    if (40..=128).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        GitHead::Commit {
            value: value.to_ascii_lowercase(),
        }
    } else {
        GitHead::Unavailable
    }
}

fn ensure_relative_path(path: &Path) -> Result<(), GatewayError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(GatewayError::UnsafeStatePath);
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, relative: &Path) -> Result<(), GatewayError> {
    ensure_relative_path(relative)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(GatewayError::UnsafeStatePath);
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(GatewayError::UnsafeStatePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reject_symlink_file(path: &Path) -> Result<(), GatewayError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(GatewayError::UnsafeStatePath),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_new_file(path: &Path, raw: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_owner_only_create_mode(&mut options);
    let mut file = options.open(path)?;
    set_owner_only_file(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    Ok(())
}

fn set_owner_only_create_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        let _ = options;
    }
}

fn set_owner_only_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn set_owner_only_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn remove_if_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            fs::remove_file(path)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn modified_seconds(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn state_usage(root: &Path) -> Result<u64, GatewayError> {
    let mut total = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(GatewayError::UnsafeStatePath);
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
                if total > MAX_STATE_BYTES {
                    return Ok(total);
                }
            } else {
                return Err(GatewayError::UnsafeStatePath);
            }
        }
    }
    Ok(total)
}

fn workspace_path(workspace: &Path, normalized: &str) -> Result<PathBuf, GatewayError> {
    let workspace = fs::canonicalize(workspace)?;
    let mut path = workspace.to_path_buf();
    for component in normalized.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(GatewayError::UnsafeStatePath);
        }
        path.push(component);
    }
    let canonical = fs::canonicalize(&path)?;
    if !canonical.starts_with(workspace) || !canonical.is_file() {
        return Err(GatewayError::UnsafeStatePath);
    }
    Ok(canonical)
}

fn run_bounded_process(
    workspace: &Path,
    search: &ExactSearch,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ProcessStatus, GatewayError> {
    let mut command = Command::new("rg");
    command
        .args(search.argv())
        .current_dir(workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or(GatewayError::InvalidInput("rg stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(GatewayError::InvalidInput("rg stderr is unavailable"))?;
    let total = Arc::new(AtomicUsize::new(0));
    let overflowed = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_capture_reader(
        stdout,
        stdout_path.to_path_buf(),
        Arc::clone(&total),
        Arc::clone(&overflowed),
    );
    let stderr_reader = spawn_capture_reader(
        stderr,
        stderr_path.to_path_buf(),
        Arc::clone(&total),
        Arc::clone(&overflowed),
    );

    let started = Instant::now();
    let mut timed_out = false;
    let exit = loop {
        if overflowed.load(Ordering::Acquire) || started.elapsed() >= EXECUTOR_TIMEOUT {
            timed_out = started.elapsed() >= EXECUTOR_TIMEOUT;
            let _ = child.kill();
            break child.wait()?;
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout_result = stdout_reader
        .join()
        .map_err(|_| GatewayError::InvalidInput("stdout capture thread panicked"))?;
    let stderr_result = stderr_reader
        .join()
        .map_err(|_| GatewayError::InvalidInput("stderr capture thread panicked"))?;
    stdout_result?;
    stderr_result?;
    Ok(ProcessStatus {
        exit_code: exit.code(),
        overflowed: overflowed.load(Ordering::Acquire),
        timed_out,
    })
}

fn spawn_capture_reader<R: Read + Send + 'static>(
    mut reader: R,
    path: PathBuf,
    total: Arc<AtomicUsize>,
    overflowed: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        set_owner_only_create_mode(&mut options);
        let mut file = options.open(&path)?;
        set_owner_only_file(&path)?;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let prior = total.fetch_add(read, Ordering::AcqRel);
            let available = MAX_RAW_SEARCH_BYTES.saturating_sub(prior);
            if available < read {
                overflowed.store(true, Ordering::Release);
            }
            if available > 0 {
                file.write_all(&buffer[..available.min(read)])?;
            }
        }
        file.sync_all()
    })
}

fn parse_raw_records(raw: &[u8], workspace: &Path) -> Result<Vec<RawRecord>, ()> {
    let mut records = Vec::new();
    for raw_line in raw.split_inclusive(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        if line == b"--" {
            continue;
        }
        if line.is_empty() {
            return Err(());
        }
        let record = parse_raw_record(line, workspace)?;
        records.push(record);
        if records.len() > MAX_RAW_MATCH_LOCATIONS {
            return Err(());
        }
    }
    if records.is_empty() {
        return Err(());
    }
    Ok(records)
}

fn parse_raw_record(raw: &[u8], workspace: &Path) -> Result<RawRecord, ()> {
    let mut candidates = Vec::new();
    for index in 0..raw.len() {
        let delimiter = raw[index];
        if delimiter != b':' && delimiter != b'-' {
            continue;
        }
        let digits_start = index + 1;
        let mut digits_end = digits_start;
        while digits_end < raw.len() && raw[digits_end].is_ascii_digit() {
            digits_end += 1;
        }
        if digits_end == digits_start || digits_end >= raw.len() || raw[digits_end] != delimiter {
            continue;
        }
        let path = std::str::from_utf8(&raw[..index]).map_err(|_| ())?;
        let lookup_path = normalize_raw_relative_path(path)?;
        if workspace_path(workspace, &lookup_path).is_err() {
            continue;
        }
        let line = std::str::from_utf8(&raw[digits_start..digits_end])
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|line| *line > 0)
            .ok_or(())?;
        candidates.push((
            path.to_owned(),
            lookup_path,
            line,
            delimiter,
            digits_end + 1,
        ));
    }
    if candidates.len() != 1 {
        return Err(());
    }
    let (_display_path, lookup_path, line, delimiter, content_start) = candidates.pop().ok_or(())?;
    Ok(RawRecord {
        display_path: lookup_path,
        line,
        kind: if delimiter == b':' {
            RecordKind::Match
        } else {
            RecordKind::Context
        },
        bytes: raw[content_start..].to_vec(),
    })
}

fn normalize_raw_relative_path(path: &str) -> Result<String, ()> {
    if path.is_empty() || path.as_bytes().contains(&0) {
        return Err(());
    }
    let path = path.replace('\\', "/");
    let path = path.strip_prefix("./").unwrap_or(&path);
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(());
    }
    Ok(path.to_owned())
}

fn render_projection(packet: &InternalContextPacketV1) -> Result<String, ProjectionError> {
    if !is_identifier(&packet.query) || packet.records.is_empty() || packet.raw_bytes == 0 {
        return Err(ProjectionError::Invalid);
    }
    let mut grouped = BTreeMap::<&str, Vec<&RawRecord>>::new();
    for record in &packet.records {
        if std::str::from_utf8(&record.bytes).is_err() || record.bytes.contains(&0) {
            return Err(ProjectionError::Invalid);
        }
        grouped
            .entry(&record.display_path)
            .or_default()
            .push(record);
    }
    let mut text = String::new();
    text.push_str("query ");
    text.push_str(&packet.query);
    text.push('\n');
    for (path, records) in grouped {
        text.push_str(path);
        text.push_str(":\n");
        for record in records {
            let source =
                std::str::from_utf8(&record.bytes).map_err(|_| ProjectionError::Invalid)?;
            text.push_str("  ");
            text.push_str(&record.line.to_string());
            text.push(if record.kind == RecordKind::Match {
                ':'
            } else {
                '-'
            });
            text.push_str(source);
            text.push('\n');
        }
    }
    if text.len() > MAX_MODEL_PROJECTION_BYTES {
        return Err(ProjectionError::TooLarge);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    use tempfile::TempDir;

    fn fixture_workspace() -> (TempDir, Gateway) {
        let temp = tempfile::tempdir().unwrap();
        let init = Command::new("git")
            .args(["init", "--quiet", "--initial-branch", "main"])
            .current_dir(temp.path())
            .status()
            .unwrap();
        assert!(init.success());
        let commit = Command::new("git")
            .args([
                "-c",
                "user.name=Cabal Test",
                "-c",
                "user.email=cabal@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "fixture",
            ])
            .current_dir(temp.path())
            .status()
            .unwrap();
        assert!(commit.success());
        let git = temp.path().join(".git");
        fs::create_dir_all(temp.path().join("src")).unwrap();
        let gateway = Gateway::open(temp.path(), &git).unwrap();
        (temp, gateway)
    }

    fn write_repeated_fixture(workspace: &Path) {
        let source = include_str!("../tests/fixtures/search_fixture/src/repeated.rs");
        fs::write(workspace.join("src/repeated.rs"), source).unwrap();
    }

    #[test]
    fn exact_parser_accepts_only_three_safe_identifier_forms() {
        for command in [
            "rg -n -C 8 -- Needle .",
            "rg -n -C 8 -- 'Needle_2' .",
            "rg -n -C 8 -- \"Needle_2\" .",
        ] {
            assert_eq!(
                parse_exact_search(command).unwrap().identifier(),
                if command.contains("Needle_2") {
                    "Needle_2"
                } else {
                    "Needle"
                }
            );
        }
        for command in [
            "rg -n -C 8 -- Needle . ",
            "rg -n -C 8 -- Needle src",
            "RG -n -C 8 -- Needle .",
            "rg -n -C 8 -- 'Needle\\' .",
            "rg -n -C 8 -- Needle.* .",
            "rg  -n -C 8 -- Needle .",
            "rg -n -C 8 -- Needle .\nwhoami",
        ] {
            assert!(parse_exact_search(command).is_none(), "{command}");
        }
    }

    #[test]
    fn observer_frame_contains_only_lifecycle_fields_and_replaces_session_frame() {
        let (_temp, gateway) = fixture_workspace();
        gateway.register_frame("session-1", Some("turn-1")).unwrap();
        let session = digest_id("session-1").unwrap();
        let path = gateway.frame_path(&session);
        let first = fs::read_to_string(&path).unwrap();
        assert!(first.contains("session_digest"));
        assert!(first.contains("turn_digest"));
        assert!(!first.contains("session-1"));
        assert!(!first.contains("prompt"));
        assert!(!first.contains(&gateway.workspace().display().to_string()));
        gateway.register_frame("session-1", Some("turn-2")).unwrap();
        let second = fs::read_to_string(path).unwrap();
        assert_ne!(first, second);
        assert!(!second.contains("turn-2"));
    }

    #[test]
    fn request_is_csprng_shaped_bound_and_consumed_once() {
        let (temp, gateway) = fixture_workspace();
        gateway.register_frame("session-1", None).unwrap();
        let prepared = gateway
            .prepare_request("session-1", temp.path(), "rg -n -C 8 -- Needle .")
            .unwrap()
            .unwrap();
        assert!(is_request_token(prepared.token()));
        assert!(gateway.request_path(prepared.token()).is_file());
        let first = gateway.execute_request(prepared.token());
        assert!(matches!(
            first,
            Outcome::RawReplay { .. } | Outcome::Projection { .. }
        ));
        assert!(matches!(
            gateway.execute_request(prepared.token()),
            Outcome::Rejected {
                reason: RequestRejection::Missing
            }
        ));
    }

    #[test]
    fn projection_is_lossless_grouped_and_strictly_smaller() {
        let (temp, gateway) = fixture_workspace();
        write_repeated_fixture(temp.path());
        gateway.register_frame("session-1", Some("turn-1")).unwrap();
        let request = gateway
            .prepare_request("session-1", temp.path(), "rg -n -C 8 -- CausalNeedle .")
            .unwrap()
            .unwrap();
        let outcome = gateway.execute_request(request.token());
        let Outcome::Projection { text, exit_code } = outcome else {
            panic!("expected grouped projection");
        };
        assert_eq!(exit_code, 0);
        assert!(text.starts_with("query CausalNeedle\n"));
        let raw = Command::new("rg")
            .args(["-n", "-C", "8", "--", "CausalNeedle", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(raw.status.success());
        let mut expected = parse_raw_records(&raw.stdout, temp.path())
            .unwrap()
            .into_iter()
            .map(|record| (record.display_path, record.line, record.kind, record.bytes))
            .collect::<Vec<_>>();
        let mut actual = Vec::new();
        let mut current_path = None;
        for line in text.lines().skip(1) {
            if let Some(path) = line
                .strip_suffix(':')
                .filter(|line| !line.starts_with("  "))
            {
                current_path = Some(path.to_owned());
                continue;
            }
            let record = line.strip_prefix("  ").expect("grouped record");
            let delimiter = record.find([':', '-']).expect("line number delimiter");
            let kind = if record.as_bytes()[delimiter] == b':' {
                RecordKind::Match
            } else {
                RecordKind::Context
            };
            actual.push((
                current_path.clone().expect("path header"),
                record[..delimiter].parse::<u64>().unwrap(),
                kind,
                record.as_bytes()[delimiter + 1..].to_vec(),
            ));
        }
        expected.sort_by_key(|(path, line, kind, bytes)| {
            (
                path.clone(),
                *line,
                *kind == RecordKind::Match,
                bytes.clone(),
            )
        });
        actual.sort_by_key(|(path, line, kind, bytes)| {
            (
                path.clone(),
                *line,
                *kind == RecordKind::Match,
                bytes.clone(),
            )
        });
        assert_eq!(actual, expected);
        assert!(!text.contains("cabal-runtime"));
        assert!(!text.contains(&temp.path().display().to_string()));
    }

    #[test]
    fn projection_rejects_nul_bytes_required_by_posix_shell_wire() {
        let packet = InternalContextPacketV1 {
            query: "Needle".to_owned(),
            records: vec![RawRecord {
                display_path: "src/lib.rs".to_owned(),
                line: 1,
                kind: RecordKind::Match,
                bytes: b"pub struct Needle;\0".to_vec(),
            }],
            raw_bytes: 32,
        };
        assert!(matches!(
            render_projection(&packet),
            Err(ProjectionError::Invalid)
        ));
    }

    #[test]
    fn small_raw_result_replays_and_preserves_rg_status() {
        let (temp, gateway) = fixture_workspace();
        fs::write(temp.path().join("src/small.rs"), "pub struct TinyNeedle;\n").unwrap();
        gateway.register_frame("session-1", None).unwrap();
        let request = gateway
            .prepare_request("session-1", temp.path(), "rg -n -C 8 -- TinyNeedle .")
            .unwrap()
            .unwrap();
        assert!(matches!(
            gateway.execute_request(request.token()),
            Outcome::RawReplay {
                reason: ReplayReason::ProjectionNotSmaller,
                captured_exit_code: Some(0),
                ..
            }
        ));
    }

    #[test]
    fn projection_uses_only_the_captured_record_bytes() {
        let (_temp, gateway) = fixture_workspace();
        let packet = InternalContextPacketV1 {
            query: "CapturedNeedle".to_owned(),
            records: vec![RawRecord {
                display_path: "src/captured.rs".to_owned(),
                line: 7,
                kind: RecordKind::Match,
                bytes: b"pub struct CapturedNeedle;".to_vec(),
            }],
            raw_bytes: 100,
        };
        fs::write(
            gateway.workspace().join("src/captured.rs"),
            "pub struct DifferentNeedle;\n",
        )
        .unwrap();

        let text = render_projection(&packet).unwrap();
        assert!(text.contains("pub struct CapturedNeedle;"));
        assert!(!text.contains("DifferentNeedle"));
    }

    #[test]
    fn malformed_and_oversized_requests_are_deleted_before_rejection() {
        let (_temp, gateway) = fixture_workspace();
        let malformed = "a".repeat(64);
        fs::write(gateway.request_path(&malformed), b"not json").unwrap();
        assert!(matches!(
            gateway.execute_request(&malformed),
            Outcome::Rejected {
                reason: RequestRejection::Malformed
            }
        ));
        assert!(!gateway.request_path(&malformed).exists());
        let oversized = "b".repeat(64);
        fs::write(
            gateway.request_path(&oversized),
            vec![b'x'; MAX_PRIVATE_REQUEST_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(
            gateway.execute_request(&oversized),
            Outcome::Rejected {
                reason: RequestRejection::Oversized
            }
        ));
        assert!(!gateway.request_path(&oversized).exists());
    }

    #[test]
    fn raw_parser_rejects_ambiguous_and_non_relative_records() {
        let (temp, _gateway) = fixture_workspace();
        fs::write(temp.path().join("src/file.rs"), "Needle\n").unwrap();
        assert!(parse_raw_records(b"src/file.rs:1:Needle\n", temp.path()).is_ok());
        assert!(parse_raw_records(b"src/file.rs:1:a:2:b\n", temp.path()).is_ok());
        assert!(parse_raw_records(b"../secret.rs:1:Needle\n", temp.path()).is_err());
        assert!(parse_raw_records(b"src/file.rs:1:Needle\n--\n", temp.path()).is_ok());
    }

    #[test]
    fn cleanup_removes_expired_and_orphaned_state_without_following_traversal() {
        let (_temp, gateway) = fixture_workspace();
        let frame = gateway.frame_path(&"c".repeat(64));
        fs::write(&frame, br#"{"version":1,"session_digest":"x","git_head":{"status":"unavailable"},"registered_at":0,"expires_at":0}"#).unwrap();
        let request = gateway.request_path(&"d".repeat(64));
        fs::write(&request, br#"{"version":1,"session_digest":"x","git_head":{"status":"unavailable"},"identifier":"Needle","created_at":0,"expires_at":0}"#).unwrap();
        let orphan_frame = gateway
            .state_root
            .join(FRAME_DIRECTORY)
            .join(".interrupted.tmp");
        fs::write(&orphan_frame, br#"{"version":1}"#).unwrap();
        let verification = gateway
            .state_root
            .join(VERIFY_DIRECTORY)
            .join("interrupted");
        fs::create_dir(&verification).unwrap();
        fs::write(verification.join("snapshot"), b"orphan").unwrap();
        let report = gateway.cleanup().unwrap();
        assert_eq!(report.expired_frames, 1);
        assert_eq!(report.expired_requests, 1);
        assert_eq!(report.orphan_verification_entries, 1);
        assert_eq!(report.malformed_files, 1);
        assert!(!orphan_frame.exists());
        assert!(!verification.exists());
        assert!(ensure_relative_path(Path::new("../escape")).is_err());
        assert!(ensure_relative_path(Path::new("requests/../escape")).is_err());
    }

    #[test]
    fn observer_frame_write_respects_the_aggregate_state_bound() {
        let (_temp, gateway) = fixture_workspace();
        let capacity = gateway.state_root.join(RAW_DIRECTORY).join("capacity");
        File::create(&capacity)
            .unwrap()
            .set_len(MAX_STATE_BYTES)
            .unwrap();

        assert!(matches!(
            gateway.register_frame("bounded-session", None),
            Err(GatewayError::StateLimit)
        ));
        assert!(
            fs::read_dir(gateway.state_root.join(FRAME_DIRECTORY))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn concurrent_requests_leave_bounded_clean_private_state() {
        let (temp, gateway) = fixture_workspace();
        write_repeated_fixture(temp.path());
        let workspace = temp.path().to_path_buf();
        let workers = (0..4)
            .map(|index| {
                let gateway = gateway.clone();
                let workspace = workspace.clone();
                thread::spawn(move || {
                    let session = format!("concurrent-session-{index}");
                    gateway.register_frame(&session, None).unwrap();
                    let request = gateway
                        .prepare_request(&session, &workspace, "rg -n -C 8 -- CausalNeedle .")
                        .unwrap()
                        .unwrap();
                    assert!(matches!(
                        gateway.execute_request(request.token()),
                        Outcome::Projection { .. }
                    ));
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }

        assert!(gateway.state_usage().unwrap() <= MAX_STATE_BYTES);
        assert!(
            fs::read_dir(gateway.state_root.join(REQUEST_DIRECTORY))
                .unwrap()
                .next()
                .is_none()
        );
        assert!(
            fs::read_dir(gateway.state_root.join(RAW_DIRECTORY))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn cwd_and_near_miss_fail_open_before_state_mutation() {
        let (temp, gateway) = fixture_workspace();
        gateway.register_frame("session-1", None).unwrap();
        let nested = temp.path().join("src");
        assert!(
            gateway
                .prepare_request("session-1", &nested, "rg -n -C 8 -- Needle .")
                .unwrap()
                .is_none()
        );
        assert!(
            gateway
                .prepare_request(
                    "session-1",
                    temp.path(),
                    "rg -n -C 8 -- Needle .; echo nope"
                )
                .unwrap()
                .is_none()
        );
        assert!(
            fs::read_dir(gateway.state_root.join(REQUEST_DIRECTORY))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn git_head_change_before_executor_requires_replay() {
        let (temp, gateway) = fixture_workspace();
        gateway.register_frame("session-1", None).unwrap();
        let request = gateway
            .prepare_request("session-1", temp.path(), "rg -n -C 8 -- Needle .")
            .unwrap()
            .unwrap();
        fs::write(
            temp.path().join(".git/refs/heads/main"),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd\n",
        )
        .unwrap();
        assert!(matches!(
            gateway.execute_request(request.token()),
            Outcome::RawReplay {
                reason: ReplayReason::RevisionStale,
                captured_exit_code: None,
                ..
            }
        ));
    }

    #[test]
    fn packed_ref_head_change_requires_replay() {
        let (temp, gateway) = fixture_workspace();
        let packed = Command::new("git")
            .args(["pack-refs", "--all", "--prune"])
            .current_dir(temp.path())
            .status()
            .unwrap();
        assert!(packed.success());
        gateway.register_frame("session-packed", None).unwrap();
        let request = gateway
            .prepare_request(
                "session-packed",
                temp.path(),
                "rg -n -C 8 -- PackedNeedle .",
            )
            .unwrap()
            .unwrap();
        let commit = Command::new("git")
            .args([
                "-c",
                "user.name=Cabal Test",
                "-c",
                "user.email=cabal@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "change packed head",
            ])
            .current_dir(temp.path())
            .status()
            .unwrap();
        assert!(commit.success());
        assert!(matches!(
            gateway.execute_request(request.token()),
            Outcome::RawReplay {
                reason: ReplayReason::RevisionStale,
                ..
            }
        ));
    }

    #[test]
    fn linked_worktree_head_change_requires_replay() {
        let root = tempfile::tempdir().unwrap();
        let primary = root.path().join("primary");
        let linked = root.path().join("linked");
        fs::create_dir(&primary).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "--quiet", "--initial-branch", "main"])
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "user.name=Cabal Test",
                    "-c",
                    "user.email=cabal@example.invalid",
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "primary",
                ])
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .args(["worktree", "add", "--quiet", "-b", "linked"])
                .arg(&linked)
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );
        let git_dir = resolve_git_service_root(&linked).unwrap();
        let gateway = Gateway::open(&linked, &git_dir).unwrap();
        gateway.register_frame("session-linked", None).unwrap();
        let request = gateway
            .prepare_request("session-linked", &linked, "rg -n -C 8 -- LinkedNeedle .")
            .unwrap()
            .unwrap();
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "user.name=Cabal Test",
                    "-c",
                    "user.email=cabal@example.invalid",
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "linked change",
                ])
                .current_dir(&linked)
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(
            gateway.execute_request(request.token()),
            Outcome::RawReplay {
                reason: ReplayReason::RevisionStale,
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_state_is_owner_only_on_unix() {
        let (temp, gateway) = fixture_workspace();
        gateway.register_frame("session-mode", None).unwrap();
        let request = gateway
            .prepare_request("session-mode", temp.path(), "rg -n -C 8 -- ModeNeedle .")
            .unwrap()
            .unwrap();
        let directory_mode = fs::metadata(&gateway.state_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let frame = fs::read_dir(gateway.state_root.join(FRAME_DIRECTORY))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let frame_mode = fs::metadata(frame).unwrap().permissions().mode() & 0o777;
        let request_mode = fs::metadata(gateway.request_path(request.token()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let lock_mode = fs::metadata(gateway.state_root.join(STATE_LOCK))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(frame_mode, 0o600);
        assert_eq!(request_mode, 0o600);
        assert_eq!(lock_mode, 0o600);
    }
}
