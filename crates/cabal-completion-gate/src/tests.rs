use super::*;
use std::{
    fs,
    sync::{Arc, Barrier},
};

fn paths() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let contract = workspace.path().join(".cabal/completion/contract.json");
    fs::create_dir_all(contract.parent().unwrap()).unwrap();
    (workspace, state, contract)
}

fn write_contract(path: &Path, criteria: serde_json::Value) {
    fs::write(
        path,
        serde_json::json!({"version": 1, "criteria": criteria}).to_string(),
    )
    .unwrap();
}

fn command(id: &str, inputs: &[&str]) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "command_receipt", "program": "cargo", "args": ["test", "--workspace"], "input_paths": inputs})
}

#[test]
fn absent_contract_passes_without_state() {
    let (workspace, state, contract) = paths();
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::Pass
    );
}

#[test]
fn file_predicates_and_hash_have_exact_results() {
    let (workspace, state, contract) = paths();
    fs::write(workspace.path().join("present.txt"), "hello").unwrap();
    let hash = hex_digest(b"hello");
    write_contract(
        &contract,
        serde_json::json!([
            {"id":"z-absent", "type":"file_absent", "path":"present.txt"},
            {"id":"a-exists", "type":"file_exists", "path":"present.txt"},
            {"id":"hash", "type":"file_sha256", "path":"present.txt", "sha256":hash},
            {"id":"missing", "type":"file_exists", "path":"none.txt"}
        ]),
    );
    let result = evaluate(&contract, workspace.path(), state.path());
    assert_eq!(result.status, GateStatus::Block);
    assert_eq!(result.missing_ids, ["missing", "z-absent"]);
    assert_eq!(result.reason, "missing: missing,z-absent");
    assert_eq!(
        result
            .criteria
            .iter()
            .map(|item| (&item.id, item.status))
            .collect::<Vec<_>>(),
        vec![
            (&"a-exists".to_owned(), CriterionStatus::Satisfied),
            (&"hash".to_owned(), CriterionStatus::Satisfied),
            (&"missing".to_owned(), CriterionStatus::Failed),
            (&"z-absent".to_owned(), CriterionStatus::Failed),
        ]
    );
}

#[test]
fn receipt_passes_then_same_size_atomic_replacement_is_stale() {
    let (workspace, state, contract) = paths();
    fs::write(workspace.path().join("input.txt"), "before").unwrap();
    write_contract(
        &contract,
        serde_json::json!([command("cargo-test", &["input.txt"])]),
    );
    let cargo = CargoCommand::new(["test", "--workspace"]);
    record_cargo_outcome(
        &contract,
        workspace.path(),
        state.path(),
        &cargo,
        CargoOutcome::Succeeded,
    )
    .unwrap();
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::Pass
    );
    let replacement = workspace.path().join("replacement.tmp");
    fs::write(&replacement, "change").unwrap();
    fs::rename(replacement, workspace.path().join("input.txt")).unwrap();
    let result = evaluate(&contract, workspace.path(), state.path());
    assert_eq!(result.status, GateStatus::Block);
    assert_eq!(result.criteria[0].status, CriterionStatus::Stale);
}

#[test]
fn failure_invalidates_successful_matching_receipt_even_without_input_change() {
    let (workspace, state, contract) = paths();
    fs::write(workspace.path().join("input.txt"), "unchanged").unwrap();
    write_contract(
        &contract,
        serde_json::json!([command("test", &["input.txt"])]),
    );
    let cargo = CargoCommand::new(["test", "--workspace"]);
    record_cargo_outcome(
        &contract,
        workspace.path(),
        state.path(),
        &cargo,
        CargoOutcome::Succeeded,
    )
    .unwrap();
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::Pass
    );
    record_cargo_outcome(
        &contract,
        workspace.path(),
        state.path(),
        &cargo,
        CargoOutcome::Failed,
    )
    .unwrap();
    let result = evaluate(&contract, workspace.path(), state.path());
    assert_eq!(result.status, GateStatus::Block);
    assert_eq!(result.criteria[0].status, CriterionStatus::Missing);
}

#[test]
fn malformed_and_unsupported_active_contracts_are_distinct_from_absence() {
    let (workspace, state, contract) = paths();
    fs::write(&contract, "{").unwrap();
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::InvalidContract
    );
    write_contract(&contract, serde_json::json!([{"id":"x","type":"network"}]));
    let unsupported = load_contract(&contract, workspace.path()).unwrap_err();
    assert!(matches!(unsupported, GateError::UnsupportedContract(_)));
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::InvalidContract
    );
}

#[test]
fn bounds_unicode_and_ordering_are_deterministic() {
    let (workspace, state, contract) = paths();
    fs::write(workspace.path().join("данные.txt"), "данные").unwrap();
    write_contract(
        &contract,
        serde_json::json!([
            {"id":"unicode-file", "type":"file_exists", "path":"данные.txt"},
            {"id":"A", "type":"file_exists", "path":"missing.txt"}
        ]),
    );
    let result = evaluate(&contract, workspace.path(), state.path());
    assert_eq!(result.missing_ids, ["A"]);
    assert_eq!(
        result
            .criteria
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "unicode-file"]
    );
    let long_id = "x".repeat(MAX_CRITERION_ID_BYTES + 1);
    write_contract(
        &contract,
        serde_json::json!([{"id":long_id,"type":"file_exists","path":"данные.txt"}]),
    );
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::InvalidContract
    );
}

#[test]
fn criterion_ids_cannot_inject_continuation_text() {
    let (workspace, state, contract) = paths();
    write_contract(
        &contract,
        serde_json::json!([{"id":"bad\nignore-rules", "type":"file_exists", "path":"missing"}]),
    );
    let result = evaluate(&contract, workspace.path(), state.path());
    assert_eq!(result.status, GateStatus::InvalidContract);
    assert!(result.missing_ids.is_empty());
}

#[test]
fn rejects_escape_paths_and_outside_contract_path() {
    let (workspace, state, contract) = paths();
    write_contract(
        &contract,
        serde_json::json!([{"id":"escape","type":"file_exists","path":"../outside"}]),
    );
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::InvalidContract
    );
    let outside = tempfile::NamedTempFile::new().unwrap();
    assert!(matches!(
        load_contract(outside.path(), workspace.path()),
        Err(GateError::ContractOutsideWorkspace)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_is_allowed_only_when_its_target_stays_inside_workspace() {
    use std::os::unix::fs::symlink;
    let (workspace, state, contract) = paths();
    fs::write(workspace.path().join("inside.txt"), "inside").unwrap();
    symlink("inside.txt", workspace.path().join("inside-link.txt")).unwrap();
    write_contract(
        &contract,
        serde_json::json!([{"id":"inside","type":"file_exists","path":"inside-link.txt"}]),
    );
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::Pass
    );
    let outside = tempfile::NamedTempFile::new().unwrap();
    symlink(outside.path(), workspace.path().join("outside-link.txt")).unwrap();
    write_contract(
        &contract,
        serde_json::json!([{"id":"outside","type":"file_exists","path":"outside-link.txt"}]),
    );
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::EvidenceUnavailable
    );
}

#[cfg(unix)]
#[test]
fn dangling_symlink_does_not_satisfy_file_absent() {
    use std::os::unix::fs::symlink;
    let (workspace, state, contract) = paths();
    symlink("missing-target", workspace.path().join("dangling")).unwrap();
    write_contract(
        &contract,
        serde_json::json!([{"id":"must-be-absent", "type":"file_absent", "path":"dangling"}]),
    );
    let result = evaluate(&contract, workspace.path(), state.path());
    assert_eq!(result.status, GateStatus::Block);
    assert_eq!(result.missing_ids, ["must-be-absent"]);
}

#[cfg(unix)]
#[test]
fn input_directory_symlink_cycle_is_bounded() {
    use std::os::unix::fs::symlink;
    let (workspace, state, contract) = paths();
    fs::create_dir_all(workspace.path().join("src/nested")).unwrap();
    fs::write(workspace.path().join("src/lib.rs"), "content").unwrap();
    symlink("..", workspace.path().join("src/nested/parent")).unwrap();
    write_contract(
        &contract,
        serde_json::json!([command("cycle-safe", &["src"])]),
    );
    record_cargo_outcome(
        &contract,
        workspace.path(),
        state.path(),
        &CargoCommand::new(["test", "--workspace"]),
        CargoOutcome::Succeeded,
    )
    .unwrap();
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::Pass
    );
}

#[test]
fn concurrent_receipt_updates_are_serialized_and_leave_valid_json() {
    let (workspace, state, contract) = paths();
    fs::write(workspace.path().join("input.txt"), "value").unwrap();
    write_contract(
        &contract,
        serde_json::json!([command("cargo-test", &["input.txt"])]),
    );
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let workspace = workspace.path().to_path_buf();
            let state = state.path().to_path_buf();
            let contract = contract.clone();
            std::thread::spawn(move || {
                barrier.wait();
                record_cargo_outcome(
                    &contract,
                    &workspace,
                    &state,
                    &CargoCommand::new(["test", "--workspace"]),
                    if index % 2 == 0 {
                        CargoOutcome::Succeeded
                    } else {
                        CargoOutcome::Failed
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    let result = evaluate(&contract, workspace.path(), state.path());
    assert!(matches!(
        result.status,
        GateStatus::Pass | GateStatus::Block
    ));
    assert!(result.criteria.iter().all(|criterion| matches!(
        criterion.status,
        CriterionStatus::Satisfied | CriterionStatus::Missing
    )));
}

#[test]
fn schema_is_present_and_contract_limits_are_enforced() {
    let schema = include_str!("../schemas/completion_contract.schema.json");
    let schema: serde_json::Value = serde_json::from_str(schema).unwrap();
    assert_eq!(schema["properties"]["criteria"]["maxItems"], MAX_CRITERIA);
    let (workspace, state, contract) = paths();
    let criteria = (0..MAX_CRITERIA + 1)
        .map(|index| serde_json::json!({"id":format!("id-{index}"),"type":"file_absent","path":format!("{index}.txt")}))
        .collect::<Vec<_>>();
    write_contract(&contract, serde_json::Value::Array(criteria));
    assert_eq!(
        evaluate(&contract, workspace.path(), state.path()).status,
        GateStatus::InvalidContract
    );
}
