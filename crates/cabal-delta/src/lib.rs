//! Deterministic normalization of an already captured unified Git diff.
//!
//! This crate never invokes Git. It stores raw diff bytes as an artifact and
//! returns a compact structural projection suitable for later internal routing.

#![forbid(unsafe_code)]

use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "cabal.delta_pack.v2";
pub const MAX_FILES: usize = 128;
pub const MAX_HUNKS_PER_FILE: usize = 64;
pub const MAX_HUNKS_TOTAL: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaVerdict {
    Clean,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileClassification {
    Manifest,
    Source,
    Test,
    Generated,
    Lockfile,
    Documentation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    TypeChanged,
    Unmerged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hunk {
    pub old_start: u64,
    pub old_lines: u64,
    pub new_start: u64,
    pub new_lines: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    pub change_kind: ChangeKind,
    pub classification: FileClassification,
    pub is_binary: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunks: Vec<Hunk>,
    pub additions: u64,
    pub deletions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaSummary {
    pub files_changed: u64,
    pub files_added: u64,
    pub files_deleted: u64,
    pub files_renamed: u64,
    pub binary_files: u64,
    pub additions: u64,
    pub deletions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawArtifact {
    pub uri: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaPack {
    pub schema: String,
    pub operation: String,
    pub verdict: DeltaVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileDelta>,
    pub summary: DeltaSummary,
    pub completeness: String,
    pub omitted_files: u64,
    pub omitted_hunks: u64,
    #[serde(skip_serializing)]
    pub raw_artifact: RawArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEntry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_status: Option<StatusKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree_status: Option<StatusKind>,
    pub untracked: bool,
    pub classification: FileClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSummary {
    pub files_changed: u64,
    pub staged: u64,
    pub unstaged: u64,
    pub untracked: u64,
    pub conflicts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStatusPack {
    pub entries: Vec<StatusEntry>,
    pub summary: StatusSummary,
    pub completeness: String,
    pub omitted_files: u64,
    #[serde(skip_serializing)]
    pub raw_artifact: RawArtifact,
}

#[derive(Debug)]
pub enum DeltaError {
    Io(io::Error),
    InvalidUtf8(std::string::FromUtf8Error),
    UnsupportedQuotedPath(String),
    MalformedDiffHeader(String),
    MalformedHunk(String),
    MalformedStatus(String),
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidUtf8(error) => write!(formatter, "diff is not valid UTF-8: {error}"),
            Self::UnsupportedQuotedPath(line) => {
                write!(formatter, "quoted Git path syntax is not supported: {line}")
            }
            Self::MalformedDiffHeader(line) => write!(formatter, "malformed diff header: {line}"),
            Self::MalformedHunk(line) => write!(formatter, "malformed diff hunk: {line}"),
            Self::MalformedStatus(line) => write!(formatter, "malformed Git status: {line}"),
        }
    }
}

impl std::error::Error for DeltaError {}

impl From<io::Error> for DeltaError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<std::string::FromUtf8Error> for DeltaError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::InvalidUtf8(error)
    }
}

#[derive(Debug)]
struct FileBuilder {
    old_path: Option<String>,
    new_path: Option<String>,
    change_kind: ChangeKind,
    is_binary: bool,
    hunks: Vec<Hunk>,
    additions: u64,
    deletions: u64,
}

impl FileBuilder {
    fn from_header(line: &str) -> Result<Self, DeltaError> {
        let paths = line
            .strip_prefix("diff --git ")
            .ok_or_else(|| DeltaError::MalformedDiffHeader(line.to_owned()))?;
        if paths.contains('"') {
            return Err(DeltaError::UnsupportedQuotedPath(line.to_owned()));
        }

        let (old_path, new_path) = paths
            .split_once(" b/")
            .ok_or_else(|| DeltaError::MalformedDiffHeader(line.to_owned()))?;
        let old_path = old_path
            .strip_prefix("a/")
            .ok_or_else(|| DeltaError::MalformedDiffHeader(line.to_owned()))?;
        if old_path.is_empty() || new_path.is_empty() {
            return Err(DeltaError::UnsupportedQuotedPath(line.to_owned()));
        }

        Ok(Self {
            old_path: Some(old_path.to_owned()),
            new_path: Some(new_path.to_owned()),
            change_kind: ChangeKind::Modified,
            is_binary: false,
            hunks: Vec::new(),
            additions: 0,
            deletions: 0,
        })
    }

    fn finish(self) -> FileDelta {
        let classification = classify_path(
            self.new_path
                .as_deref()
                .or(self.old_path.as_deref())
                .unwrap_or_default(),
        );
        FileDelta {
            old_path: self.old_path,
            new_path: self.new_path,
            change_kind: self.change_kind,
            classification,
            is_binary: self.is_binary,
            hunks: self.hunks,
            additions: self.additions,
            deletions: self.deletions,
        }
    }
}

pub fn normalize_file(input: &Path, artifact_root: &Path) -> Result<DeltaPack, DeltaError> {
    normalize_bytes(&fs::read(input)?, artifact_root)
}

pub fn normalize_bytes(raw: &[u8], artifact_root: &Path) -> Result<DeltaPack, DeltaError> {
    let raw_artifact = persist_raw_artifact(raw, artifact_root)?;
    let diff = String::from_utf8(raw.to_vec())?;
    let mut files = parse_unified_diff(&diff)?;
    if !diff.trim().is_empty() && files.is_empty() {
        return Err(DeltaError::MalformedDiffHeader(
            "non-empty output contained no diff header".to_owned(),
        ));
    }
    let summary = summarize(&files);
    let mut omitted_hunks = 0;
    let mut remaining_hunks = MAX_HUNKS_TOTAL;
    for file in &mut files {
        let retained = file
            .hunks
            .len()
            .min(MAX_HUNKS_PER_FILE)
            .min(remaining_hunks);
        omitted_hunks += file.hunks.len().saturating_sub(retained) as u64;
        file.hunks.truncate(retained);
        remaining_hunks -= retained;
    }
    let omitted_files = files.len().saturating_sub(MAX_FILES) as u64;
    files.truncate(MAX_FILES);
    let complete = omitted_files == 0 && omitted_hunks == 0;

    Ok(DeltaPack {
        schema: SCHEMA_VERSION.to_owned(),
        operation: "git-diff".to_owned(),
        verdict: if files.is_empty() {
            DeltaVerdict::Clean
        } else {
            DeltaVerdict::Changed
        },
        files,
        summary,
        completeness: if complete {
            "all supported unified-diff file boundaries, hunk ranges, statuses, and patch-line counts retained"
        } else {
            "bounded projection; omitted file or hunk counts are reported"
        }
        .to_owned(),
        omitted_files,
        omitted_hunks,
        raw_artifact,
    })
}

pub fn normalize_status_bytes(
    raw: &[u8],
    artifact_root: &Path,
) -> Result<GitStatusPack, DeltaError> {
    let raw_artifact = persist_raw_artifact(raw, artifact_root)?;
    let text = String::from_utf8(raw.to_vec())?;
    let records = text.split('\0').collect::<Vec<_>>();
    let mut entries = Vec::new();
    let mut index = 0;
    while index < records.len() {
        let record = records[index];
        index += 1;
        if record.is_empty() {
            continue;
        }
        let entry = if let Some(path) = record.strip_prefix("? ") {
            StatusEntry {
                path: path.to_owned(),
                original_path: None,
                index_status: None,
                worktree_status: None,
                untracked: true,
                classification: classify_path(path),
            }
        } else if record.starts_with("1 ") {
            let fields = record.splitn(9, ' ').collect::<Vec<_>>();
            if fields.len() != 9 {
                return Err(DeltaError::MalformedStatus(record.to_owned()));
            }
            status_entry(fields[1], fields[8], None)?
        } else if record.starts_with("2 ") {
            let fields = record.splitn(10, ' ').collect::<Vec<_>>();
            if fields.len() != 10 {
                return Err(DeltaError::MalformedStatus(record.to_owned()));
            }
            let original_path = records
                .get(index)
                .filter(|path| !path.is_empty())
                .ok_or_else(|| DeltaError::MalformedStatus(record.to_owned()))?;
            index += 1;
            status_entry(fields[1], fields[9], Some((*original_path).to_owned()))?
        } else if record.starts_with("u ") {
            let fields = record.splitn(11, ' ').collect::<Vec<_>>();
            if fields.len() != 11 {
                return Err(DeltaError::MalformedStatus(record.to_owned()));
            }
            let mut entry = status_entry(fields[1], fields[10], None)?;
            entry.index_status = Some(StatusKind::Unmerged);
            entry.worktree_status = Some(StatusKind::Unmerged);
            entry
        } else if record.starts_with("! ") {
            continue;
        } else {
            return Err(DeltaError::MalformedStatus(record.to_owned()));
        };
        entries.push(entry);
    }

    let summary = summarize_status(&entries);
    let omitted_files = entries.len().saturating_sub(MAX_FILES) as u64;
    entries.truncate(MAX_FILES);
    Ok(GitStatusPack {
        entries,
        summary,
        completeness: if omitted_files == 0 {
            "all porcelain-v2 status entries retained"
        } else {
            "bounded projection; omitted status entry count is reported"
        }
        .to_owned(),
        omitted_files,
        raw_artifact,
    })
}

fn status_entry(
    xy: &str,
    path: &str,
    original_path: Option<String>,
) -> Result<StatusEntry, DeltaError> {
    let mut chars = xy.chars();
    let index_status = status_kind(chars.next().unwrap_or('.'));
    let worktree_status = status_kind(chars.next().unwrap_or('.'));
    if chars.next().is_some() {
        return Err(DeltaError::MalformedStatus(xy.to_owned()));
    }
    Ok(StatusEntry {
        path: path.to_owned(),
        original_path,
        index_status,
        worktree_status,
        untracked: false,
        classification: classify_path(path),
    })
}

fn status_kind(code: char) -> Option<StatusKind> {
    match code {
        '.' => None,
        'A' => Some(StatusKind::Added),
        'M' => Some(StatusKind::Modified),
        'D' => Some(StatusKind::Deleted),
        'R' => Some(StatusKind::Renamed),
        'C' => Some(StatusKind::Copied),
        'T' => Some(StatusKind::TypeChanged),
        'U' => Some(StatusKind::Unmerged),
        _ => Some(StatusKind::Unknown),
    }
}

fn summarize_status(entries: &[StatusEntry]) -> StatusSummary {
    StatusSummary {
        files_changed: entries.len() as u64,
        staged: entries
            .iter()
            .filter(|entry| entry.index_status.is_some())
            .count() as u64,
        unstaged: entries
            .iter()
            .filter(|entry| entry.worktree_status.is_some())
            .count() as u64,
        untracked: entries.iter().filter(|entry| entry.untracked).count() as u64,
        conflicts: entries
            .iter()
            .filter(|entry| {
                entry.index_status == Some(StatusKind::Unmerged)
                    || entry.worktree_status == Some(StatusKind::Unmerged)
            })
            .count() as u64,
    }
}

pub fn classify_path(path: &str) -> FileClassification {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    if matches!(
        name,
        "cargo.toml" | "package.json" | "pyproject.toml" | "go.mod" | "build.gradle" | "pom.xml"
    ) {
        FileClassification::Manifest
    } else if name.ends_with(".lock") || matches!(name, "cargo.lock" | "package-lock.json") {
        FileClassification::Lockfile
    } else if normalized.contains("/generated/")
        || normalized.starts_with("generated/")
        || normalized.contains("/target/")
        || normalized.contains("/dist/")
    {
        FileClassification::Generated
    } else if normalized.contains("/tests/")
        || normalized.starts_with("tests/")
        || name.ends_with("_test.rs")
        || name.ends_with(".test.ts")
        || name.ends_with(".spec.ts")
    {
        FileClassification::Test
    } else if matches!(
        name.rsplit_once('.').map(|(_, extension)| extension),
        Some(
            "rs" | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
                | "go"
                | "py"
                | "js"
                | "ts"
                | "tsx"
                | "java"
                | "kt"
        )
    ) {
        FileClassification::Source
    } else if matches!(
        name.rsplit_once('.').map(|(_, extension)| extension),
        Some("md" | "rst" | "txt" | "adoc")
    ) {
        FileClassification::Documentation
    } else {
        FileClassification::Other
    }
}

fn persist_raw_artifact(raw: &[u8], artifact_root: &Path) -> Result<RawArtifact, io::Error> {
    let hash = format!("{:x}", Sha256::digest(raw));
    let directory = artifact_root.join(&hash);
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("raw-output"), raw)?;

    Ok(RawArtifact {
        uri: format!("artifact://delta/{hash}/raw-output"),
        sha256: hash,
        bytes: raw.len() as u64,
    })
}

fn parse_unified_diff(diff: &str) -> Result<Vec<FileDelta>, DeltaError> {
    let mut files = Vec::new();
    let mut current: Option<FileBuilder> = None;

    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            if let Some(builder) = current.take() {
                files.push(builder.finish());
            }
            current = Some(FileBuilder::from_header(line)?);
            continue;
        }

        let Some(builder) = current.as_mut() else {
            continue;
        };

        if line == "new file mode 100644" || line.starts_with("new file mode ") {
            builder.change_kind = ChangeKind::Added;
        } else if line == "deleted file mode 100644" || line.starts_with("deleted file mode ") {
            builder.change_kind = ChangeKind::Deleted;
        } else if let Some(path) = line.strip_prefix("rename from ") {
            builder.old_path = Some(path.to_owned());
            builder.change_kind = ChangeKind::Renamed;
        } else if let Some(path) = line.strip_prefix("rename to ") {
            builder.new_path = Some(path.to_owned());
            builder.change_kind = ChangeKind::Renamed;
        } else if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            builder.is_binary = true;
        } else if let Some(path) = line.strip_prefix("--- ") {
            builder.old_path = marker_path(path);
            if builder.old_path.is_none() {
                builder.change_kind = ChangeKind::Added;
            }
        } else if let Some(path) = line.strip_prefix("+++ ") {
            builder.new_path = marker_path(path);
            if builder.new_path.is_none() {
                builder.change_kind = ChangeKind::Deleted;
            }
        } else if line.starts_with("@@ ") {
            builder.hunks.push(parse_hunk(line)?);
        } else if line.starts_with('+') && !line.starts_with("+++") {
            builder.additions += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            builder.deletions += 1;
        }
    }

    if let Some(builder) = current {
        files.push(builder.finish());
    }

    Ok(files)
}

fn marker_path(value: &str) -> Option<String> {
    let value = value.trim_end_matches('\t');
    if value == "/dev/null" {
        return None;
    }

    value
        .strip_prefix("a/")
        .or_else(|| value.strip_prefix("b/"))
        .map(str::to_owned)
}

fn parse_hunk(line: &str) -> Result<Hunk, DeltaError> {
    let ranges = line
        .strip_prefix("@@ ")
        .and_then(|rest| rest.split_once(" @@").map(|(ranges, _)| ranges))
        .ok_or_else(|| DeltaError::MalformedHunk(line.to_owned()))?;
    let mut parts = ranges.split_whitespace();
    let old_range = parts
        .next()
        .ok_or_else(|| DeltaError::MalformedHunk(line.to_owned()))?;
    let new_range = parts
        .next()
        .ok_or_else(|| DeltaError::MalformedHunk(line.to_owned()))?;
    if parts.next().is_some() {
        return Err(DeltaError::MalformedHunk(line.to_owned()));
    }

    let (old_start, old_lines) = parse_range(old_range, '-', line)?;
    let (new_start, new_lines) = parse_range(new_range, '+', line)?;
    Ok(Hunk {
        old_start,
        old_lines,
        new_start,
        new_lines,
    })
}

fn parse_range(value: &str, prefix: char, source: &str) -> Result<(u64, u64), DeltaError> {
    let value = value
        .strip_prefix(prefix)
        .ok_or_else(|| DeltaError::MalformedHunk(source.to_owned()))?;
    let (start, count) = match value.split_once(',') {
        Some((start, count)) => (start, count),
        None => (value, "1"),
    };
    let start = start
        .parse()
        .map_err(|_| DeltaError::MalformedHunk(source.to_owned()))?;
    let count = count
        .parse()
        .map_err(|_| DeltaError::MalformedHunk(source.to_owned()))?;
    Ok((start, count))
}

fn summarize(files: &[FileDelta]) -> DeltaSummary {
    let mut summary = DeltaSummary {
        files_changed: files.len() as u64,
        files_added: 0,
        files_deleted: 0,
        files_renamed: 0,
        binary_files: 0,
        additions: 0,
        deletions: 0,
    };

    for file in files {
        match file.change_kind {
            ChangeKind::Added => summary.files_added += 1,
            ChangeKind::Deleted => summary.files_deleted += 1,
            ChangeKind::Renamed => summary.files_renamed += 1,
            ChangeKind::Modified => {}
        }
        summary.binary_files += u64::from(file.is_binary);
        summary.additions += file.additions;
        summary.deletions += file.deletions;
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_modified_file_hunks_and_patch_counts() {
        let raw = b"diff --git a/src/lib.rs b/src/lib.rs\nindex aaa..bbb 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -10,2 +10,3 @@ fn run() {\n-old\n+new\n+extra\n context\n@@ -30 +31 @@ fn finish() {\n-before\n+after\n";
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(raw, artifacts.path()).unwrap();
        let file = pack.files.first().unwrap();

        assert_eq!(pack.verdict, DeltaVerdict::Changed);
        assert_eq!(file.change_kind, ChangeKind::Modified);
        assert_eq!(file.hunks.len(), 2);
        assert_eq!(file.hunks[0].old_start, 10);
        assert_eq!(file.hunks[0].new_lines, 3);
        assert_eq!(file.additions, 3);
        assert_eq!(file.deletions, 2);
        assert!(
            artifacts
                .path()
                .join(&pack.raw_artifact.sha256)
                .join("raw-output")
                .is_file()
        );
    }

    #[test]
    fn distinguishes_add_delete_rename_and_binary_files() {
        let raw = b"diff --git a/new.rs b/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/new.rs\n@@ -0,0 +1 @@\n+new\ndiff --git a/old.rs b/old.rs\ndeleted file mode 100644\n--- a/old.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\ndiff --git a/old_name.rs b/new_name.rs\nsimilarity index 100%\nrename from old_name.rs\nrename to new_name.rs\ndiff --git a/image.bin b/image.bin\nBinary files a/image.bin and b/image.bin differ\n";
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(raw, artifacts.path()).unwrap();

        assert_eq!(pack.files.len(), 4);
        assert_eq!(pack.files[0].change_kind, ChangeKind::Added);
        assert_eq!(pack.files[0].old_path, None);
        assert_eq!(pack.files[1].change_kind, ChangeKind::Deleted);
        assert_eq!(pack.files[1].new_path, None);
        assert_eq!(pack.files[2].change_kind, ChangeKind::Renamed);
        assert_eq!(pack.files[3].change_kind, ChangeKind::Modified);
        assert!(pack.files[3].is_binary);
        assert_eq!(pack.summary.files_added, 1);
        assert_eq!(pack.summary.files_deleted, 1);
        assert_eq!(pack.summary.files_renamed, 1);
        assert_eq!(pack.summary.binary_files, 1);
    }

    #[test]
    fn empty_diff_is_clean() {
        let artifacts = tempfile::tempdir().unwrap();

        let pack = normalize_bytes(b"", artifacts.path()).unwrap();

        assert_eq!(pack.verdict, DeltaVerdict::Clean);
        assert!(pack.files.is_empty());
    }

    #[test]
    fn rejects_quoted_git_paths_instead_of_guessing() {
        let artifacts = tempfile::tempdir().unwrap();
        let raw = b"diff --git \"a/file with space.rs\" \"b/file with space.rs\"\n";

        assert!(matches!(
            normalize_bytes(raw, artifacts.path()),
            Err(DeltaError::UnsupportedQuotedPath(_))
        ));
    }

    #[test]
    fn preserves_spaces_and_unicode_when_git_disables_path_quoting() {
        let artifacts = tempfile::tempdir().unwrap();
        let raw = "diff --git a/old name.rs b/юникод name.rs\nrename from old name.rs\nrename to юникод name.rs\n";

        let pack = normalize_bytes(raw.as_bytes(), artifacts.path()).unwrap();

        assert_eq!(pack.files[0].old_path.as_deref(), Some("old name.rs"));
        assert_eq!(pack.files[0].new_path.as_deref(), Some("юникод name.rs"));
        assert_eq!(pack.files[0].change_kind, ChangeKind::Renamed);
        assert_eq!(pack.files[0].classification, FileClassification::Source);
    }

    #[test]
    fn parses_porcelain_v2_staged_unstaged_untracked_and_rename() {
        let artifacts = tempfile::tempdir().unwrap();
        let raw = concat!(
            "1 M. N... 100644 100644 100644 aaaaaaa bbbbbbb Cargo.toml\0",
            "1 .M N... 100644 100644 100644 aaaaaaa bbbbbbb src/lib.rs\0",
            "2 R. N... 100644 100644 100644 aaaaaaa bbbbbbb R100 юникод name.rs\0old name.rs\0",
            "? tests/new test.rs\0"
        );

        let pack = normalize_status_bytes(raw.as_bytes(), artifacts.path()).unwrap();

        assert_eq!(pack.summary.files_changed, 4);
        assert_eq!(pack.summary.staged, 2);
        assert_eq!(pack.summary.unstaged, 1);
        assert_eq!(pack.summary.untracked, 1);
        assert_eq!(pack.entries[0].classification, FileClassification::Manifest);
        assert_eq!(pack.entries[1].classification, FileClassification::Source);
        assert_eq!(
            pack.entries[2].original_path.as_deref(),
            Some("old name.rs")
        );
        assert_eq!(pack.entries[3].classification, FileClassification::Test);
    }

    #[test]
    fn malformed_nonempty_outputs_never_become_clean() {
        let artifacts = tempfile::tempdir().unwrap();
        assert!(matches!(
            normalize_bytes(b"fatal: not a repository", artifacts.path()),
            Err(DeltaError::MalformedDiffHeader(_))
        ));
        assert!(matches!(
            normalize_status_bytes(b"unexpected\0", artifacts.path()),
            Err(DeltaError::MalformedStatus(_))
        ));
    }

    #[test]
    fn projections_are_bounded_with_explicit_omissions() {
        let artifacts = tempfile::tempdir().unwrap();
        let raw = (0..(MAX_FILES + 3))
            .map(|index| format!("? generated/file-{index}.rs\0"))
            .collect::<String>();

        let pack = normalize_status_bytes(raw.as_bytes(), artifacts.path()).unwrap();

        assert_eq!(pack.entries.len(), MAX_FILES);
        assert_eq!(pack.summary.files_changed, (MAX_FILES + 3) as u64);
        assert_eq!(pack.omitted_files, 3);
        assert!(pack.completeness.contains("bounded"));
    }

    #[test]
    fn diff_hunks_obey_per_file_and_global_limits() {
        let artifacts = tempfile::tempdir().unwrap();
        let mut raw = String::new();
        for file in 0..5 {
            raw.push_str(&format!("diff --git a/file-{file}.rs b/file-{file}.rs\n"));
            for hunk in 0..70 {
                raw.push_str(&format!(
                    "@@ -{},1 +{},1 @@\n-old\n+new\n",
                    hunk + 1,
                    hunk + 1
                ));
            }
        }

        let pack = normalize_bytes(raw.as_bytes(), artifacts.path()).unwrap();
        let retained = pack
            .files
            .iter()
            .map(|file| file.hunks.len())
            .sum::<usize>();

        assert_eq!(retained, MAX_HUNKS_TOTAL);
        assert_eq!(pack.omitted_hunks, 350 - MAX_HUNKS_TOTAL as u64);
        assert!(pack.completeness.contains("bounded"));
    }
}
