//! Session-aware observations for bounded UTF-8 text file reads.

#![forbid(unsafe_code)]

use std::{
    fs,
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::{DiffTag, TextDiff};

pub const MAX_FILE_BYTES: u64 = 262_144;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_SLICE_BYTES: usize = 65_536;
pub const MAX_SLICE_LINES: u64 = 400;
pub const MAX_CHANGED_RANGES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestedRange {
    Full,
    Lines { start: u64, end: u64 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Content,
    Unchanged,
    Changed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangedRange {
    pub old_start: u64,
    pub old_lines: u64,
    pub new_start: u64,
    pub new_lines: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileObservation {
    pub status: ObservationStatus,
    pub path: String,
    pub requested: RequestedRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_ranges: Vec<ChangedRange>,
    pub omitted_changed_ranges: u64,
    pub completeness: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheEntry {
    content_hash: String,
    snapshot: PathBuf,
    bytes: u64,
    modified_nanos: Option<u128>,
    observed: Vec<ObservedRange>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct ObservedRange {
    start: u64,
    end: u64,
}

#[derive(Debug)]
pub enum CacheError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidUtf8,
    OutsideWorkspace,
    NotFile,
    FileTooLarge,
    PathTooLong,
    InvalidRange,
    SliceTooLarge,
    ConcurrentChange,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "file cache I/O: {error}"),
            Self::Json(error) => write!(formatter, "file cache JSON: {error}"),
            Self::InvalidUtf8 => write!(formatter, "file is not valid UTF-8 text"),
            Self::OutsideWorkspace => write!(formatter, "file is outside the workspace"),
            Self::NotFile => write!(formatter, "path is not a regular file"),
            Self::FileTooLarge => write!(formatter, "file exceeds the cache byte limit"),
            Self::PathTooLong => write!(formatter, "path exceeds the cache byte limit"),
            Self::InvalidRange => write!(formatter, "requested line range is invalid"),
            Self::SliceTooLarge => write!(formatter, "requested slice exceeds a cache limit"),
            Self::ConcurrentChange => write!(formatter, "file changed during observation"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<io::Error> for CacheError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CacheError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn supports_file(path: &Path, workspace: &Path) -> bool {
    inspect_supported_file(path, workspace).is_ok()
}

pub fn supports_request(path: &Path, workspace: &Path, requested: RequestedRange) -> bool {
    let Ok(()) = validate_range(requested) else {
        return false;
    };
    let Ok((_, raw, _)) = inspect_supported_file(path, workspace) else {
        return false;
    };
    let Ok(content) = std::str::from_utf8(&raw) else {
        return false;
    };
    let Ok(slice) = slice_content(content, requested) else {
        return false;
    };
    requested == RequestedRange::Full || slice.len() <= MAX_SLICE_BYTES
}

pub fn observe_file(
    path: &Path,
    workspace: &Path,
    state_root: &Path,
    session_id: &str,
    requested: RequestedRange,
) -> Result<FileObservation, CacheError> {
    validate_range(requested)?;
    let (canonical, raw, metadata) = inspect_supported_file(path, workspace)?;
    let content = std::str::from_utf8(&raw).map_err(|_| CacheError::InvalidUtf8)?;
    let requested_content = slice_content(content, requested)?;
    if requested_content.len() > MAX_SLICE_BYTES && requested != RequestedRange::Full {
        return Err(CacheError::SliceTooLarge);
    }

    let content_hash = format!("{:x}", Sha256::digest(&raw));
    let cache_key = format!(
        "{:x}",
        Sha256::digest(
            [
                session_id.as_bytes(),
                b"\0",
                canonical.to_string_lossy().as_bytes()
            ]
            .concat()
        )
    );
    let entries = state_root.join("entries");
    let snapshots = state_root.join("snapshots");
    let _lock = lock_state(state_root)?;
    fs::create_dir_all(&entries)?;
    fs::create_dir_all(&snapshots)?;
    let entry_path = entries.join(format!("{cache_key}.json"));
    let previous = read_entry(&entry_path)?;
    let observed_range = actual_observed_range(content, requested);

    let (status, changed_ranges, omitted_changed_ranges, observed) = match previous {
        Some(previous) if previous.content_hash == content_hash => {
            if is_covered(&previous.observed, observed_range) {
                (
                    ObservationStatus::Unchanged,
                    Vec::new(),
                    0,
                    previous.observed,
                )
            } else {
                let mut observed = previous.observed;
                merge_range(&mut observed, observed_range);
                (ObservationStatus::Content, Vec::new(), 0, observed)
            }
        }
        Some(previous) => {
            let old = fs::read_to_string(previous.snapshot).unwrap_or_default();
            let (ranges, omitted) = changed_ranges(&old, content);
            let mut observed = Vec::new();
            merge_range(&mut observed, observed_range);
            (ObservationStatus::Changed, ranges, omitted, observed)
        }
        None => {
            let mut observed = Vec::new();
            merge_range(&mut observed, observed_range);
            (ObservationStatus::Content, Vec::new(), 0, observed)
        }
    };

    if status == ObservationStatus::Unchanged {
        return Ok(FileObservation {
            status,
            path: relative_display_path(&canonical, workspace),
            requested,
            content: None,
            changed_ranges,
            omitted_changed_ranges,
            completeness: "requested range is unchanged and already observed in this session"
                .to_owned(),
        });
    }

    let snapshot_path = snapshots.join(format!("{content_hash}.utf8"));
    if !snapshot_path.exists() {
        fs::write(&snapshot_path, &raw)?;
    }
    let entry = CacheEntry {
        content_hash,
        snapshot: snapshot_path,
        bytes: metadata.len(),
        modified_nanos: modified_nanos(&metadata),
        observed,
    };
    write_entry(&entry_path, &entry)?;

    Ok(FileObservation {
        status,
        path: relative_display_path(&canonical, workspace),
        requested,
        content: Some(requested_content.to_owned()),
        changed_ranges,
        omitted_changed_ranges,
        completeness: if status == ObservationStatus::Changed {
            "requested current content and bounded changed line ranges retained"
        } else {
            "requested current content retained"
        }
        .to_owned(),
    })
}

pub fn invalidate_observations(state_root: &Path) -> Result<(), CacheError> {
    let _lock = lock_state(state_root)?;
    for directory in ["entries", "snapshots"] {
        let path = state_root.join(directory);
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

fn inspect_supported_file(
    path: &Path,
    workspace: &Path,
) -> Result<(PathBuf, Vec<u8>, fs::Metadata), CacheError> {
    let workspace = fs::canonicalize(workspace)?;
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(&workspace) {
        return Err(CacheError::OutsideWorkspace);
    }
    if canonical.to_string_lossy().len() > MAX_PATH_BYTES {
        return Err(CacheError::PathTooLong);
    }
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(CacheError::NotFile);
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(CacheError::FileTooLarge);
    }
    let raw = read_stable(&canonical)?;
    std::str::from_utf8(&raw).map_err(|_| CacheError::InvalidUtf8)?;
    Ok((canonical, raw, metadata))
}

fn read_stable(path: &Path) -> Result<Vec<u8>, CacheError> {
    for _ in 0..3 {
        let before = fs::metadata(path)?;
        let first = fs::read(path)?;
        let middle = fs::metadata(path)?;
        let second = fs::read(path)?;
        let after = fs::metadata(path)?;
        if first == second
            && before.len() == first.len() as u64
            && middle.len() == first.len() as u64
            && after.len() == first.len() as u64
            && modified_nanos(&before) == modified_nanos(&middle)
            && modified_nanos(&middle) == modified_nanos(&after)
        {
            return Ok(first);
        }
    }
    Err(CacheError::ConcurrentChange)
}

fn lock_state(state_root: &Path) -> Result<fs::File, CacheError> {
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

fn validate_range(requested: RequestedRange) -> Result<(), CacheError> {
    if let RequestedRange::Lines { start, end } = requested
        && (start == 0 || end < start || end - start + 1 > MAX_SLICE_LINES)
    {
        return Err(CacheError::InvalidRange);
    }
    Ok(())
}

fn line_spans(content: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            spans.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < content.len() {
        spans.push((start, content.len()));
    }
    spans
}

fn slice_content(content: &str, requested: RequestedRange) -> Result<&str, CacheError> {
    let RequestedRange::Lines { start, end } = requested else {
        return Ok(content);
    };
    let spans = line_spans(content);
    if spans.is_empty() || start as usize > spans.len() {
        return Ok("");
    }
    let first = spans[start as usize - 1].0;
    let last_index = (end as usize).min(spans.len()) - 1;
    Ok(&content[first..spans[last_index].1])
}

fn actual_observed_range(content: &str, requested: RequestedRange) -> ObservedRange {
    let line_count = line_spans(content).len() as u64;
    match requested {
        RequestedRange::Full => ObservedRange {
            start: 1,
            end: line_count.max(1),
        },
        RequestedRange::Lines { start, end } => ObservedRange { start, end },
    }
}

fn is_covered(observed: &[ObservedRange], requested: ObservedRange) -> bool {
    observed
        .iter()
        .any(|range| range.start <= requested.start && range.end >= requested.end)
}

fn merge_range(observed: &mut Vec<ObservedRange>, requested: ObservedRange) {
    observed.push(requested);
    observed.sort_by_key(|range| range.start);
    let mut merged: Vec<ObservedRange> = Vec::new();
    for range in observed.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *observed = merged;
}

fn changed_ranges(old: &str, new: &str) -> (Vec<ChangedRange>, u64) {
    let diff = TextDiff::from_lines(old, new);
    let mut ranges = diff
        .ops()
        .iter()
        .filter(|operation| operation.tag() != DiffTag::Equal)
        .map(|operation| {
            let old = operation.old_range();
            let new = operation.new_range();
            ChangedRange {
                old_start: old.start as u64 + 1,
                old_lines: old.len() as u64,
                new_start: new.start as u64 + 1,
                new_lines: new.len() as u64,
            }
        })
        .collect::<Vec<_>>();
    let omitted = ranges.len().saturating_sub(MAX_CHANGED_RANGES) as u64;
    ranges.truncate(MAX_CHANGED_RANGES);
    (ranges, omitted)
}

fn read_entry(path: &Path) -> Result<Option<CacheEntry>, CacheError> {
    match fs::read(path) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_entry(path: &Path, entry: &CacheEntry) -> Result<(), CacheError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("{nonce}.tmp"));
    fs::write(&temporary, serde_json::to_vec(entry)?)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn modified_nanos(metadata: &fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

fn relative_display_path(path: &Path, workspace: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests;
