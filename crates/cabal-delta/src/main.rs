use std::{env, path::PathBuf, process::ExitCode};

use cabal_delta::normalize_file;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cabal-delta: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    if command != "normalize" {
        return Err(usage());
    }

    let mut input = None;
    let mut artifacts = PathBuf::from(".cabal/artifacts");

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--input" => {
                input = Some(PathBuf::from(
                    arguments.next().ok_or("--input needs a path")?,
                ))
            }
            "--artifacts" => {
                artifacts = PathBuf::from(arguments.next().ok_or("--artifacts needs a path")?)
            }
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("unknown argument {argument:?}\n{}", usage())),
        }
    }

    let input = input.ok_or_else(usage)?;
    let delta = normalize_file(&input, &artifacts).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&delta).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: cabal-delta normalize --input <unified-diff-path> [--artifacts <path>]".to_owned()
}
