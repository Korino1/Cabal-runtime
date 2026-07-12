use std::env;
use std::io::{self, Read};
use std::path::PathBuf;

use cabal_runtime_hook::{
    HookOutput, PostToolUseInput, PreToolUseInput, execute_cargo_request, fallback_output,
    prepare_pre_tool_use, project_post_tool_use,
};

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    match args.next().as_deref() {
        Some(command) if command == "pre-tool-use" => run_pre_tool_use(),
        Some(command) if command == "execute-cargo" => run_execute_cargo(args),
        Some(_) => print_output(fallback_output()),
        None => run_post_tool_use(),
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
