use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio, Termination};

use anyhow::{ensure, Context, Result};
use cli::ExecArgs;
use itertools::Itertools;
use named_lock::NamedLock;
use owo_colors::OwoColorize;

use crate::sysconf::{SysConf, SysConfArgs};

pub mod cli;
pub mod sysconf;

const SERVICE_NAME: &str = "cbench.service";
const SYSTEMD_RUN: &str = "systemd-run";

const SETUP_SENTINEL: &str = "__cbench_setup";

pub fn maybe_run_setup() {
    let mut args_iter = std::env::args_os();
    if args_iter.next().is_some_and(|arg| arg == SETUP_SENTINEL) {
        let is_enter = args_iter.next().expect("setup arg must be given") == "1";
        let confs = std::env::var(SETUP_SENTINEL)
            .context("missing setup envvar")
            .and_then(|v| Ok(serde_json::from_str::<Vec<Box<dyn SysConf>>>(&v)?))
            .expect("setup args must be valid");
        let code = match main_setup(is_enter, &confs) {
            Err(err) => {
                eprintln!("{}: {err:#}", "error".red().bold());
                1
            }
            Ok(()) => 0,
        };
        std::process::exit(code);
    }
}

/// Setup and cleanup of the benchmark environment.
/// NB. This is executed with full privileges as root.
fn main_setup(is_enter: bool, confs: &[impl AsRef<dyn SysConf>]) -> Result<()> {
    // Ignore termination signals.
    ctrlc::set_handler(|| {})?;

    let print_err = |ret: Result<()>| {
        if let Err(err) = ret {
            eprintln!("{}: {:#}", "error".red().bold(), err);
        }
    };

    if is_enter {
        for conf in confs {
            print_err(conf.as_ref().enter());
        }
    } else {
        for conf in confs.iter().rev() {
            print_err(conf.as_ref().leave());
        }
    }

    Ok(())
}

pub fn main_exec(
    args: &ExecArgs,
    bench_exes: &[impl AsRef<OsStr>],
    bench_args: &[impl AsRef<OsStr>],
) -> Result<()> {
    const LOCK_NAME: &str = "cargo-cbench.lock";

    ensure!(!bench_exes.is_empty(), "nothing to bench");

    let bench_lock_path =
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").context("cannot get XDG runtime dir")?)
            .join(LOCK_NAME);
    let bench_lock = NamedLock::with_path(bench_lock_path)?;
    let _guard = bench_lock.try_lock().or_else(|_| {
        eprintln!(
            "{:>12} waiting for global benchmark lock",
            "Blocking".cyan().bold(),
        );
        bench_lock.lock()
    });

    let self_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("failed to get current executable path")?;
    let self_exe = self_exe
        .to_str()
        .context("current executable path is not UTF-8")?;

    let conf_args = SysConfArgs {
        cpus: args.cpus.iter().copied().collect(),
        isolated: args.isolated || args.cpus.len() == 1,
    };
    let confs = sysconf::ALL_MODULES
        .iter()
        .filter(|(_, name, ..)| args.is_module_enabled(name))
        .map(|&(builder, ..)| builder(&conf_args))
        .collect::<Result<Vec<_>>>()?;
    let setup_confs_json = serde_json::to_string(&confs).expect("serialization cannot fail");
    let allowed_cpus = conf_args.cpus.iter().join(",");

    for exe in bench_exes {
        let mut cmd = match &args.use_sudo {
            None => Command::new(SYSTEMD_RUN),
            Some(sudo) => Command::new(sudo),
        };
        cmd.args(args.use_sudo.is_some().then_some(SYSTEMD_RUN))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .args([
                "--collect",
                "--wait",
                // WAIT: https://github.com/systemd/systemd/issues/32916
                // It may block indefinitely when `Exec{StartPre,StopPost}` prints something.
                "--pty",
                &format!("--unit={SERVICE_NAME}"),
                // It must be in a partition=root scope to set partition=root.
                "--slice=-.slice",
                "--description=Environment Controlled Benchmarks",
                "--service-type=exec",
                "--expand-environment=no",
                "--same-dir",
                &format!("--setenv={SETUP_SENTINEL}={setup_confs_json}"),
                &format!("--property=AllowedCPUs={allowed_cpus}"),
                &format!("--property=ExecStartPre=!@{self_exe} {SETUP_SENTINEL} 1"),
                &format!("--property=ExecStopPost=!@{self_exe} {SETUP_SENTINEL} 0"),
            ]);
        if !args.root {
            cmd.args([
                &format!("--uid={}", nix::unistd::getuid().as_raw()),
                &format!("--gid={}", nix::unistd::getgid().as_raw()),
            ]);
        }
        for env in &args.setenv {
            let mut arg = OsString::from("--setenv=");
            arg.push(env);
            cmd.arg(arg);
        }

        cmd.arg("--");
        cmd.arg(exe.as_ref());
        cmd.args(bench_args);

        if args.dry_run {
            eprintln!(
                "{:>12} {}",
                "WouldRun".green().bold(),
                std::iter::once(cmd.get_program())
                    .chain(cmd.get_args())
                    .format_with(" ", |arg, f| f(&format_args!("{arg:?}"))),
            );
        } else {
            let st = cmd
                .status()
                .with_context(|| format!("failed to spawn {:?}", cmd.get_program()))?;
            exit_ok(st)?;
        }
    }

    Ok(())
}

// WAIT: Copied from unstable `std::process::ExitStatusError`.
#[derive(Debug, Clone, Copy)]
pub struct ExitStatusError(ExitStatus);
impl std::fmt::Display for ExitStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "process exited unsuccessfully: {}", self.0)
    }
}
impl std::error::Error for ExitStatusError {}
impl Termination for ExitStatusError {
    fn report(self) -> ExitCode {
        ExitCode::from((self.0.code().unwrap_or(1) as u8).max(1))
    }
}
pub fn exit_ok(status: ExitStatus) -> Result<(), ExitStatusError> {
    status
        .success()
        .then_some(())
        .ok_or(ExitStatusError(status))
}
