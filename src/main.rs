use std::{env, path::PathBuf, process::ExitCode};

use cabal_observe::{InputKind, normalize_file};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cabal-observe: {error}");
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

    let mut kind = None;
    let mut input = None;
    let mut artifacts = PathBuf::from(".cabal/artifacts");

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--kind" => kind = Some(arguments.next().ok_or("--kind needs a value")?),
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

    let kind = InputKind::parse(&kind.ok_or_else(usage)?).map_err(|error| error.to_string())?;
    let input = input.ok_or_else(usage)?;
    let observation =
        normalize_file(kind, &input, &artifacts).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&observation).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: cabal-observe normalize --kind <cargo-json|cargo-test-text> --input <path> [--artifacts <path>]".to_owned()
}
