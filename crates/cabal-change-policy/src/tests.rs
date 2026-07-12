use std::{
    fs,
    sync::{Arc, Barrier},
};

use tempfile::TempDir;

use super::*;

fn workspace() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn write_policy(workspace: &TempDir, value: serde_json::Value) {
    let path = workspace.path().join(POLICY_RELATIVE_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn policy() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "paths": {
            "allow": ["src/**", "docs/**", "internal/**", "generated/**"],
            "deny": ["secrets/**"],
            "internal": ["internal/**"],
            "generated": ["generated/**"]
        },
        "rules": {"internal": "ask", "generated": "deny"},
        "limits": {"max_patch_bytes": 1024, "max_files": 2, "max_line_changes": 4},
        "commands": {
            "allow": [["cargo", "test", "-p", "cabal-change-policy"]],
            "ask": [["cargo", "fmt"]],
            "deny": [["git", "reset", "--hard"]],
            "destructive": [["rm", "-rf", "target"]]
        }
    })
}

#[test]
fn absent_policy_is_disabled_without_a_decision() {
    let workspace = workspace();
    let result = evaluate(workspace.path(), ToolInput::Bash("cargo test"));
    assert_eq!(result.state, PolicyState::Disabled);
    assert_eq!(result.decision, None);
    assert_eq!(result.code, "policy_disabled");
}

#[test]
fn active_policy_allows_patch_and_exact_command() {
    let workspace = workspace();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    write_policy(&workspace, policy());
    let patch = "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(patch)).decision,
        Some(Decision::Allow)
    );
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::Bash("cargo test -p cabal-change-policy")
        )
        .decision,
        Some(Decision::Allow)
    );
}

#[test]
fn apply_patch_move_target_is_checked_and_trailing_data_is_rejected() {
    let workspace = workspace();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    fs::create_dir_all(workspace.path().join("secrets")).unwrap();
    write_policy(&workspace, policy());

    let denied_move = "*** Begin Patch\n*** Update File: src/lib.rs\n*** Move to: secrets/lib.rs\n@@\n-old\n+new\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(denied_move)).code,
        "path_denied"
    );

    let trailing =
        "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\nignored";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(trailing)).code,
        "malformed_patch"
    );
}

#[test]
fn indented_headers_and_environment_id_follow_codex_patch_grammar() {
    let workspace = workspace();
    for directory in ["src", "secrets"] {
        fs::create_dir_all(workspace.path().join(directory)).unwrap();
    }
    write_policy(&workspace, policy());

    let indented = "*** Begin Patch\n*** Add File: src/ok.txt\n+ok\n *** Add File: secrets/key.txt\n+secret\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(indented)).code,
        "path_denied"
    );

    let environment = " *** Begin Patch\n*** Environment ID: remote\n*** Add File: src/lib.rs\n+pub fn value() {}\n *** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(environment)).decision,
        Some(Decision::Allow)
    );
}

#[test]
fn update_context_that_looks_like_a_header_is_not_an_operation() {
    let workspace = workspace();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    write_policy(&workspace, policy());

    let patch = "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n *** Add File: secrets/key\n-old\n+new\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(patch)).decision,
        Some(Decision::Allow)
    );
}

#[test]
fn path_rules_internal_generated_and_limits_are_enforced() {
    let workspace = workspace();
    for directory in ["src", "internal", "generated", "secrets"] {
        fs::create_dir_all(workspace.path().join(directory)).unwrap();
    }
    write_policy(&workspace, policy());
    let patch = |path: &str| {
        format!("*** Begin Patch\n*** Update File: {path}\n@@\n-old\n+new\n*** End Patch\n")
    };
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::ApplyPatch(&patch("internal/a.rs"))
        )
        .decision,
        Some(Decision::Ask)
    );
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::ApplyPatch(&patch("generated/a.rs"))
        )
        .decision,
        Some(Decision::Deny)
    );
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::ApplyPatch(&patch("secrets/key"))
        )
        .code,
        "path_denied"
    );
    let large =
        "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-a\n+b\n-c\n+d\n-e\n+f\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(large)).code,
        "too_many_line_changes"
    );
}

#[test]
fn malformed_patch_cannot_hide_a_path_or_bypass_limits() {
    let workspace = workspace();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    write_policy(&workspace, policy());
    let hidden = "*** Begin Patch\n*** Update File: src/a.rs\n*** Update File: secrets/key\n@@\n-x\n+y\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(hidden)).code,
        "path_denied"
    );
    let malformed = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(malformed)).code,
        "malformed_patch"
    );
    let unsupported = "random non-patch text";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(unsupported)).code,
        "malformed_patch"
    );
}

#[test]
fn traversal_and_windows_linux_lexical_forms_are_rejected() {
    let workspace = workspace();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    write_policy(&workspace, policy());
    for path in [
        "../outside",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "\\\\server\\share\\file",
        "src/../secrets/key",
    ] {
        let patch =
            format!("*** Begin Patch\n*** Update File: {path}\n@@\n-old\n+new\n*** End Patch\n");
        assert_eq!(
            evaluate(workspace.path(), ToolInput::ApplyPatch(&patch)).code,
            "invalid_path",
            "{path}"
        );
    }
    let windows =
        "*** Begin Patch\n*** Update File: src\\portable.rs\n@@\n-old\n+new\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(windows)).decision,
        Some(Decision::Allow)
    );
}

#[cfg(unix)]
#[test]
fn symlinked_existing_ancestor_cannot_escape_workspace() {
    use std::os::unix::fs::symlink;
    let workspace = workspace();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), workspace.path().join("src/link")).unwrap();
    write_policy(&workspace, policy());
    let patch =
        "*** Begin Patch\n*** Update File: src/link/escape.rs\n@@\n-old\n+new\n*** End Patch\n";
    assert_eq!(
        evaluate(workspace.path(), ToolInput::ApplyPatch(patch)).code,
        "path_outside_workspace"
    );
}

#[test]
fn bash_grammar_handles_safe_quotes_but_rejects_shell_bypass_syntax() {
    let workspace = workspace();
    write_policy(&workspace, policy());
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::Bash("cargo 'test' -p \"cabal-change-policy\"")
        )
        .decision,
        Some(Decision::Allow)
    );
    for command in [
        "cargo test; rm -rf target",
        "cargo $(echo test)",
        "cargo test > out",
        "cargo test && rm -rf target",
    ] {
        let result = evaluate(workspace.path(), ToolInput::Bash(command));
        assert_eq!(result.decision, None, "{command}");
    }
    assert_eq!(
        evaluate(workspace.path(), ToolInput::Bash("cargo fmt")).decision,
        Some(Decision::Ask)
    );
    assert_eq!(
        evaluate(workspace.path(), ToolInput::Bash("cargo check")).decision,
        Some(Decision::Allow)
    );
    assert_eq!(
        evaluate(workspace.path(), ToolInput::Bash("rm -rf target")).decision,
        Some(Decision::Deny)
    );
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::Bash("rm -rf \"tar${EMPTY}get\"")
        )
        .decision,
        Some(Decision::Deny)
    );
    assert_eq!(
        evaluate(
            workspace.path(),
            ToolInput::Bash("custom-delete \"tar${EMPTY}get\"")
        )
        .decision,
        None
    );
}

#[test]
fn invalid_active_policy_fails_closed_with_bounded_safe_output() {
    let workspace = workspace();
    write_policy(&workspace, serde_json::json!({"version": 99}));
    let result = evaluate(workspace.path(), ToolInput::ApplyPatch("not a patch"));
    assert_eq!(result.state, PolicyState::Active);
    assert_eq!(result.decision, Some(Decision::Deny));
    assert_eq!(result.code, "invalid_policy");
    assert!(result.reason.len() <= MAX_REASON_BYTES);
    assert_eq!(
        evaluate(workspace.path(), ToolInput::Bash("cargo test")).decision,
        None
    );
    assert_eq!(
        evaluate(workspace.path(), ToolInput::Bash("git reset --hard")).decision,
        Some(Decision::Deny)
    );
}

#[test]
fn receipt_is_only_available_for_active_policy_and_updates_atomically() {
    let workspace = workspace();
    write_policy(&workspace, policy());
    let input = ToolInput::Bash("cargo test -p cabal-change-policy");
    let result = evaluate(workspace.path(), input.clone());
    let receipt = receipt_for(&result, input).unwrap();
    let written = write_receipt(workspace.path(), &receipt).unwrap();
    assert!(
        written.starts_with(
            fs::canonicalize(workspace.path())
                .unwrap()
                .join(".cabal/state/change_policy/receipts")
        )
    );
    let decoded: Receipt = serde_json::from_slice(&fs::read(written).unwrap()).unwrap();
    assert_eq!(decoded, receipt);

    let barrier = Arc::new(Barrier::new(6));
    let handles = (0..6)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let root = workspace.path().to_path_buf();
            let receipt = receipt.clone();
            std::thread::spawn(move || {
                barrier.wait();
                write_receipt(&root, &receipt)
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    let decoded: Receipt = serde_json::from_slice(
        &fs::read(
            workspace
                .path()
                .join(".cabal/state/change_policy/receipts")
                .read_dir()
                .unwrap()
                .find_map(Result::ok)
                .unwrap()
                .path(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(decoded, receipt);
}

#[cfg(unix)]
#[test]
fn receipt_state_symlink_escape_is_rejected_before_writing() {
    use std::os::unix::fs::symlink;

    let workspace = workspace();
    write_policy(&workspace, policy());
    let outside = tempfile::tempdir().unwrap();
    let state = workspace.path().join(".cabal/state");
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    symlink(outside.path(), &state).unwrap();

    let input = ToolInput::Bash("cargo test -p cabal-change-policy");
    let evaluation = evaluate(workspace.path(), input.clone());
    let receipt = receipt_for(&evaluation, input).unwrap();
    assert!(matches!(
        write_receipt(workspace.path(), &receipt),
        Err(PolicyError::StateOutsideWorkspace)
    ));
    assert!(!outside.path().join("change_policy/state.lock").exists());
}

#[test]
fn schema_tracks_the_bounded_versioned_contract() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/change_policy.schema.json")).unwrap();
    assert_eq!(schema["properties"]["version"]["const"], 1);
    assert_eq!(
        schema["$defs"]["patterns"]["maxItems"],
        MAX_PATTERNS_PER_CLASS
    );
    assert_eq!(
        schema["$defs"]["command_sets"]["items"]["maxItems"],
        MAX_COMMAND_ARGS
    );
}
