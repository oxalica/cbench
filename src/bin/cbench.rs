use std::process::{ExitCode, Termination};

use cbench::{cli, main_exec, maybe_run_setup, ExitStatusError};

fn main() -> ExitCode {
    maybe_run_setup();

    let args: cli::Args = clap::Parser::parse();
    let ret = main_exec(&args.exec_args, &args.command, &args.command_args);
    match ret {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            args.exec_args.verbosity.error(format_args!("{err:#}"));
            if let Ok(st) = err.downcast::<ExitStatusError>() {
                st.report()
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
