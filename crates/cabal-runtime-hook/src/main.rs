use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cabal_runtime_hook::{
    CausalExecution, HookOutput, PostToolUseInput, PreToolUseInput, StopInput,
    UserPromptSubmitInput, cleanup_causal_context, evaluate_stop, execute_cargo_request,
    execute_causal_request, execute_file_read_request, execute_git_request, execute_log_request,
    execute_repository_inventory_request, fallback_output, invalidate_file_read_cache,
    prepare_pre_tool_use, project_post_tool_use, refresh_repository_map, register_causal_frame,
    stop_wire_failure,
};

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    match args.next().as_deref() {
        Some(command) if command == "pre-tool-use" => run_pre_tool_use(),
        Some(command) if command == "execute-cargo" => run_execute_cargo(args),
        Some(command) if command == "execute-log" => run_execute_log(args),
        Some(command) if command == "execute-git" => run_execute_git(args),
        Some(command) if command == "execute-file-read" => run_execute_file_read(args),
        Some(command) if command == "repository-inventory" => run_repository_inventory(args),
        Some(command) if command == "causal-context" => {
            std::process::exit(run_causal_context(args, false));
        }
        Some(command) if command == "causal-context-wire" => {
            std::process::exit(run_causal_context(args, true));
        }
        Some(command) if command == "register-causal-frame" => run_register_causal_frame(),
        Some(command) if command == "cleanup-causal-context" => run_cleanup_causal_context(),
        Some(command) if command == "invalidate-file-cache" => run_invalidate_file_cache(),
        Some(command) if command == "refresh-repository-map" => run_refresh_repository_map(),
        Some(command) if command == "stop" => run_stop(),
        Some(_) => print_output(fallback_output()),
        None => run_post_tool_use(),
    }
}

fn run_cleanup_causal_context() {
    let cwd = read_stdin()
        .ok()
        .and_then(|input| serde_json::from_str::<serde_json::Value>(&input).ok())
        .and_then(|payload| {
            payload
                .get("cwd")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
        })
        .or_else(|| env::current_dir().ok());
    if let Some(cwd) = cwd {
        let _ = cleanup_causal_context(&cwd);
    }
}

fn run_register_causal_frame() {
    if let Ok(input) = read_stdin()
        && let Ok(payload) = serde_json::from_str::<UserPromptSubmitInput>(&input)
    {
        let _ = register_causal_frame(payload);
    }
}

fn run_causal_context(
    mut args: impl Iterator<Item = std::ffi::OsString>,
    encode_projection: bool,
) -> i32 {
    let Some(flag) = args.next() else {
        return 75;
    };
    let Some(token) = args.next() else {
        return 75;
    };
    if flag != "--request-id" || args.next().is_some() {
        return 75;
    }
    let Some(cwd) = env::current_dir().ok() else {
        return 75;
    };
    match execute_causal_request(&cwd, &token.to_string_lossy()) {
        Ok(CausalExecution::Projection { text, exit_code }) => {
            if encode_projection {
                print!("{}", BASE64_STANDARD.encode(text.as_bytes()));
            } else {
                print!("{text}");
            }
            let _ = io::stdout().flush();
            exit_code
        }
        Ok(CausalExecution::RawReplay { .. }) => 75,
        Ok(CausalExecution::RetryOriginal) | Err(_) => 75,
    }
}

fn run_repository_inventory(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let Some(flag) = args.next() else {
        print_output(fallback_output());
        return;
    };
    let Some(request_id) = args.next() else {
        print_output(fallback_output());
        return;
    };
    if flag != "--request-id" || args.next().is_some() {
        print_output(fallback_output());
        return;
    }

    let projection = env::current_dir().ok().and_then(|cwd| {
        execute_repository_inventory_request(&cwd, &request_id.to_string_lossy()).ok()
    });
    match projection {
        Some(projection) => println!("{projection}"),
        None => print_output(fallback_output()),
    }
}

fn run_refresh_repository_map() {
    let cwd = read_stdin()
        .ok()
        .and_then(|input| serde_json::from_str::<serde_json::Value>(&input).ok())
        .and_then(|payload| {
            payload
                .get("cwd")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
        })
        .or_else(|| env::current_dir().ok());
    if let Some(cwd) = cwd {
        let _ = refresh_repository_map(&cwd);
    }
}

fn run_stop() {
    let output = read_stdin()
        .ok()
        .and_then(|input| serde_json::from_str::<StopInput>(&input).ok())
        .map(evaluate_stop)
        .unwrap_or_else(stop_wire_failure);
    if let Ok(json) = serde_json::to_string(&output) {
        println!("{json}");
    }
}

fn run_execute_file_read(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let Some(flag) = args.next() else {
        print_output(fallback_output());
        return;
    };
    let Some(request_path) = args.next() else {
        print_output(fallback_output());
        return;
    };
    if flag != "--request" || args.next().is_some() {
        print_output(fallback_output());
        return;
    }

    match execute_file_read_request(&PathBuf::from(request_path)) {
        Ok(projection) => println!("{projection}"),
        Err(_) => print_output(fallback_output()),
    }
}

fn run_invalidate_file_cache() {
    let cwd = read_stdin()
        .ok()
        .and_then(|input| serde_json::from_str::<serde_json::Value>(&input).ok())
        .and_then(|payload| {
            payload
                .get("cwd")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
        })
        .or_else(|| env::current_dir().ok());
    if let Some(cwd) = cwd {
        let _ = invalidate_file_read_cache(&cwd);
    }
}

fn run_execute_git(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let Some(flag) = args.next() else {
        print_output(fallback_output());
        return;
    };
    let Some(request_path) = args.next() else {
        print_output(fallback_output());
        return;
    };
    if flag != "--request" || args.next().is_some() {
        print_output(fallback_output());
        return;
    }

    match execute_git_request(&PathBuf::from(request_path)) {
        Ok(projection) => println!("{projection}"),
        Err(_) => print_output(fallback_output()),
    }
}

fn run_execute_log(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let Some(flag) = args.next() else {
        print_output(fallback_output());
        return;
    };
    let Some(request_path) = args.next() else {
        print_output(fallback_output());
        return;
    };
    if flag != "--request" || args.next().is_some() {
        print_output(fallback_output());
        return;
    }

    match execute_log_request(&PathBuf::from(request_path)) {
        Ok(projection) => println!("{projection}"),
        Err(_) => print_output(fallback_output()),
    }
}

fn print_output(output: HookOutput) {
    if let Ok(json) = serde_json::to_string(&output) {
        println!("{json}");
    }
}

fn run_post_tool_use() {
    match read_stdin().and_then(|input| {
        let payload: PostToolUseInput = serde_json::from_str(&input)?;
        project_post_tool_use(payload).map_err(Into::into)
    }) {
        Ok(Some(output)) => print_output(output),
        Ok(None) => {}
        Err(_) => print_output(fallback_output()),
    }
}

fn run_pre_tool_use() {
    let result = read_stdin().and_then(|input| {
        let payload: PreToolUseInput = serde_json::from_str(&input)?;
        let executable = env::current_exe()?;
        prepare_pre_tool_use(payload, &executable).map_err(Into::into)
    });

    if let Ok(Some(output)) = result
        && let Ok(json) = serde_json::to_string(&output)
    {
        println!("{json}");
    }
}

fn run_execute_cargo(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let Some(flag) = args.next() else {
        print_output(fallback_output());
        return;
    };
    let Some(request_path) = args.next() else {
        print_output(fallback_output());
        return;
    };
    if flag != "--request" || args.next().is_some() {
        print_output(fallback_output());
        return;
    }

    match execute_cargo_request(&PathBuf::from(request_path)) {
        Ok(projection) => println!("{projection}"),
        Err(_) => print_output(fallback_output()),
    }
}

fn read_stdin() -> Result<String, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}
