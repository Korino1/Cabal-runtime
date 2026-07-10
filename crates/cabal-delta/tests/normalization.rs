use std::path::Path;

use cabal_delta::{ChangeKind, DeltaVerdict, normalize_file};

#[test]
fn fixture_retains_changed_files_hunks_and_smaller_projection() {
    let artifacts = tempfile::tempdir().unwrap();
    let fixture = Path::new("tests/fixtures/noisy-change.diff");
    let raw = std::fs::read(fixture).unwrap();
    let pack = normalize_file(fixture, artifacts.path()).unwrap();
    let projection = serde_json::to_vec(&pack).unwrap();

    assert_eq!(pack.verdict, DeltaVerdict::Changed);
    assert_eq!(pack.files.len(), 2);
    assert!(
        pack.files
            .iter()
            .all(|file| file.change_kind == ChangeKind::Modified)
    );
    assert_eq!(pack.summary.additions, 3);
    assert_eq!(pack.summary.deletions, 1);
    assert!(projection.len() < raw.len());
}
