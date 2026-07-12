use super::*;
use filetime::{FileTime, set_file_mtime};
use std::fs;
use std::sync::{Arc, Barrier};

#[test]
fn first_read_then_covered_repeat_and_new_range() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = workspace.path().join("file.txt");
    fs::write(&path, "one\r\ntwo\r\nthree\r\n").unwrap();

    let first = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "session-a",
        RequestedRange::Lines { start: 1, end: 2 },
    )
    .unwrap();
    assert_eq!(first.status, ObservationStatus::Content);
    assert_eq!(first.content.as_deref(), Some("one\r\ntwo\r\n"));

    let repeated = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "session-a",
        RequestedRange::Lines { start: 1, end: 1 },
    )
    .unwrap();
    assert_eq!(repeated.status, ObservationStatus::Unchanged);
    assert!(repeated.content.is_none());

    let new_range = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "session-a",
        RequestedRange::Lines { start: 2, end: 3 },
    )
    .unwrap();
    assert_eq!(new_range.status, ObservationStatus::Content);
    assert_eq!(new_range.content.as_deref(), Some("two\r\nthree\r\n"));
}

#[test]
fn changed_content_wins_over_same_metadata_and_restored_timestamp() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = workspace.path().join("same-size.txt");
    fs::write(&path, "alpha\nbeta\n").unwrap();
    let timestamp = FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
    observe_file(
        &path,
        workspace.path(),
        state.path(),
        "session",
        RequestedRange::Full,
    )
    .unwrap();

    let replacement = workspace.path().join("replacement.tmp");
    fs::write(&replacement, "alpha\nzeta\n").unwrap();
    fs::rename(&replacement, &path).unwrap();
    set_file_mtime(&path, timestamp).unwrap();

    let changed = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "session",
        RequestedRange::Full,
    )
    .unwrap();
    assert_eq!(changed.status, ObservationStatus::Changed);
    assert_eq!(changed.content.as_deref(), Some("alpha\nzeta\n"));
    assert_eq!(changed.changed_ranges.len(), 1);
}

#[test]
fn session_and_compact_invalidation_force_refresh() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = workspace.path().join("file.txt");
    fs::write(&path, "content\n").unwrap();

    observe_file(
        &path,
        workspace.path(),
        state.path(),
        "a",
        RequestedRange::Full,
    )
    .unwrap();
    let other = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "b",
        RequestedRange::Full,
    )
    .unwrap();
    assert_eq!(other.status, ObservationStatus::Content);

    invalidate_observations(state.path()).unwrap();
    let refreshed = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "a",
        RequestedRange::Full,
    )
    .unwrap();
    assert_eq!(refreshed.status, ObservationStatus::Content);
}

#[test]
fn unicode_bom_no_final_newline_and_rapid_rewrite_are_exact() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = workspace.path().join("юникод.txt");
    fs::write(&path, "\u{feff}один\nдва").unwrap();

    let first = observe_file(
        &path,
        workspace.path(),
        state.path(),
        "session",
        RequestedRange::Full,
    )
    .unwrap();
    assert_eq!(first.content.as_deref(), Some("\u{feff}один\nдва"));

    for value in ["три\nдва", "три\nчетыре", "пять\nчетыре"] {
        fs::write(&path, value).unwrap();
        let changed = observe_file(
            &path,
            workspace.path(),
            state.path(),
            "session",
            RequestedRange::Full,
        )
        .unwrap();
        assert_eq!(changed.status, ObservationStatus::Changed);
        assert_eq!(changed.content.as_deref(), Some(value));
    }
}

#[test]
fn rejects_invalid_utf8_outside_workspace_and_bounds() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let binary = workspace.path().join("binary.bin");
    fs::write(&binary, [0xff, 0xfe]).unwrap();
    assert!(!supports_file(&binary, workspace.path()));

    let outside = tempfile::NamedTempFile::new().unwrap();
    assert!(!supports_file(outside.path(), workspace.path()));

    let text = workspace.path().join("text.txt");
    fs::write(&text, "x\n").unwrap();
    assert!(matches!(
        observe_file(
            &text,
            workspace.path(),
            state.path(),
            "session",
            RequestedRange::Lines {
                start: 1,
                end: MAX_SLICE_LINES + 1
            }
        ),
        Err(CacheError::InvalidRange)
    ));

    let oversized = workspace.path().join("oversized.txt");
    fs::write(&oversized, vec![b'x'; MAX_FILE_BYTES as usize + 1]).unwrap();
    assert!(!supports_request(
        &oversized,
        workspace.path(),
        RequestedRange::Full
    ));
}

#[test]
fn concurrent_observers_are_serialized_without_stale_or_failed_results() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = workspace.path().join("shared.txt");
    fs::write(&path, "shared content\n").unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            let workspace = workspace.path().to_path_buf();
            let state = state.path().to_path_buf();
            std::thread::spawn(move || {
                barrier.wait();
                observe_file(
                    &path,
                    &workspace,
                    &state,
                    "shared-session",
                    RequestedRange::Full,
                )
            })
        })
        .collect::<Vec<_>>();

    let observations = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        observations
            .iter()
            .filter(|observation| observation.status == ObservationStatus::Content)
            .count(),
        1
    );
    assert_eq!(
        observations
            .iter()
            .filter(|observation| observation.status == ObservationStatus::Unchanged)
            .count(),
        7
    );
}

#[test]
fn rename_and_delete_cannot_reuse_the_old_path_observation() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let old = workspace.path().join("old.txt");
    let new = workspace.path().join("new.txt");
    fs::write(&old, "content\n").unwrap();
    observe_file(
        &old,
        workspace.path(),
        state.path(),
        "session",
        RequestedRange::Full,
    )
    .unwrap();

    fs::rename(&old, &new).unwrap();
    assert!(!supports_file(&old, workspace.path()));
    let renamed = observe_file(
        &new,
        workspace.path(),
        state.path(),
        "session",
        RequestedRange::Full,
    )
    .unwrap();
    assert_eq!(renamed.status, ObservationStatus::Content);

    fs::remove_file(&new).unwrap();
    assert!(!supports_file(&new, workspace.path()));
}
