use std::io::{self, Read};

use cabal_runtime_hook::{HookOutput, PostToolUseInput, fallback_output, project_post_tool_use};

fn main() {
    match run() {
        Ok(Some(output)) => print_output(output),
        Ok(None) => {}
        Err(_) => print_output(fallback_output()),
    }
}

fn print_output(output: HookOutput) {
    if let Ok(json) = serde_json::to_string(&output) {
        println!("{json}");
    }
}

fn run() -> Result<Option<HookOutput>, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let payload: PostToolUseInput = serde_json::from_str(&input)?;

    project_post_tool_use(payload).map_err(Into::into)
}
