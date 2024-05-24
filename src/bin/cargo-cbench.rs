use std::ffi::OsString;
use std::io::BufReader;
use std::process::{Command, ExitCode, Stdio, Termination};

use anyhow::{Context, Result};
use cargo_metadata::Message;
use cbench::{cli::ExecArgs, exit_ok, main_exec, maybe_run_setup, ExitStatusError};

#[derive(Debug, PartialEq, Eq, clap::Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Args {
    /// `cargo bench` compatible subcommand, but execute the benchmark executables in controlled
    /// environment
    Cbench(InnerArgs),
}

#[derive(Debug, Default, PartialEq, Eq, clap::Args)]
#[command(version, about, long_about = None)]
pub struct InnerArgs {
    #[command(flatten)]
    pub exec_args: ExecArgs,

    /// Options for `cargo bench`.
    /// Like its interface, arguments after `--` will be passed to each bench executables instead
    /// of to `cargo` itself.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CARGO_ARGS"
    )]
    pub rest_args: Vec<OsString>,
}

fn main() -> ExitCode {
    maybe_run_setup();

    let Args::Cbench(args) = clap::Parser::parse();
    let verbosity = args.exec_args.verbosity;
    match try_main(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            verbosity.error(format_args!("{err:#}"));
            if let Ok(st) = err.downcast::<ExitStatusError>() {
                st.report()
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn try_main(args: InnerArgs) -> Result<()> {
    let mut bench_args = vec!["--bench".into()];
    let mut cargo_args = args.rest_args;
    if let Some(pos) = cargo_args.iter().position(|arg| arg == "--") {
        bench_args.extend(cargo_args.drain((pos + 1)..));
        cargo_args.pop();
    }

    // Passthrough `-v` and `-q`.
    cargo_args.extend(args.exec_args.verbosity.iter_flags().map(Into::into));

    let mut benches = Vec::new();
    let cargo_exe = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut child = Command::new(cargo_exe)
        .args([
            "bench",
            "--message-format=json-render-diagnostics",
            "--no-run",
        ])
        .args(cargo_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn cargo")?;

    let rdr = BufReader::new(child.stdout.take().unwrap());
    for msg in Message::parse_stream(rdr) {
        let Message::CompilerArtifact(artifact) = msg? else {
            continue;
        };
        if artifact.target.kind != ["bench"] {
            continue;
        }
        let path = artifact
            .executable
            .context("missing bench executable")?
            .into_std_path_buf();
        benches.push(path);
    }
    exit_ok(child.wait()?)?;

    main_exec(&args.exec_args, &benches, &bench_args)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parse_cargo_cmd() {
        Args::try_parse_from(["cargo-cbench"]).unwrap_err();

        assert_eq!(
            Args::try_parse_from(["cargo-cbench", "cbench"]).unwrap(),
            Args::Cbench(InnerArgs::default()),
        );

        assert_eq!(
            Args::try_parse_from([
                "cargo-cbench",
                "cbench",
                "--dry-run",
                "--features=foo",
                "bench1",
                "--",
                "--test"
            ])
            .unwrap(),
            Args::Cbench(InnerArgs {
                exec_args: ExecArgs {
                    dry_run: true,
                    ..ExecArgs::default()
                },
                rest_args: vec![
                    "--features=foo".into(),
                    "bench1".into(),
                    "--".into(),
                    "--test".into()
                ],
            })
        );
    }
}
