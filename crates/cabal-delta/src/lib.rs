//! Deterministic normalization of an already captured unified Git diff.
//!
//! This crate never invokes Git. It stores raw diff bytes as an artifact and
//! returns a compact structural projection suitable for later internal routing.

use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "cabal.delta_pack.v1";

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
    pub raw_artifact: RawArtifact,
}

#[derive(Debug)]
pub enum DeltaError {
    Io(io::Error),
    InvalidUtf8(std::string::FromUtf8Error),
    UnsupportedQuotedPath(String),
    MalformedDiffHeader(String),
    MalformedHunk(String),
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
        if old_path.is_empty()
            || new_path.is_empty()
            || new_path.contains(' ')
            || old_path.contains(' ')
        {
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
        FileDelta {
            old_path: self.old_path,
            new_path: self.new_path,
            change_kind: self.change_kind,
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
    let files = parse_unified_diff(&diff)?;
    let summary = summarize(&files);

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
        completeness: "all supported unified-diff file boundaries, hunk ranges, statuses, and patch-line counts retained".to_owned(),
        raw_artifact,
    })
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
}
