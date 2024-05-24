use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio, Termination};

use anyhow::{ensure, Context, Result};
use cli::ExecArgs;
use itertools::Itertools;
use named_lock::NamedLock;
use owo_colors::{AnsiColors, OwoColorize};

use crate::sysconf::{SysConf, SysConfArgs};

pub mod cli;
pub mod sysconf;

const SERVICE_NAME: &str = "cbench.service";
const SYSTEMD_RUN: &str = "systemd-run";

const SETUP_SENTINEL: &str = "__cbench_setup";

pub fn maybe_run_setup() {
    let mut args_iter = std::env::args_os();
    if !args_iter.next().is_some_and(|arg| arg == SETUP_SENTINEL) {
        return;
    }

    let sd_pty_workaround = args_iter.next().unwrap() == "1";
    if sd_pty_workaround {
        // Workaround: reopen STDOUT and STDERR with `/dev/null`.
        // Unfortunately this suppresses all warnings and errors,
        // but I failed to come up with a better yet simple alternative.
        if let Err(_err) = (|| -> Result<_> {
            let devnull = File::open("/dev/null")?;
            nix::unistd::dup2(devnull.as_raw_fd(), 1)?;
            nix::unistd::dup2(devnull.as_raw_fd(), 2)?;
            Ok(())
        })() {
            std::process::exit(2);
        }
    }

    let is_enter = args_iter.next().unwrap() == "1";
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

/// Setup and cleanup of the benchmark environment.
/// NB. This is executed with full privileges as root.
fn main_setup(is_enter: bool, confs: &[impl AsRef<dyn SysConf>]) -> Result<()> {
    // Ignore termination signals.
    ctrlc::set_handler(|| {})?;

    // TODO: Passthrough verbosity into setup?
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
        args.verbosity.status(
            1,
            AnsiColors::Cyan,
            "Blocking",
            "waiting for global benchmark lock",
        );
        bench_lock.lock()
    });

    let self_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("failed to get current executable path")?;
    let self_exe = self_exe
        .to_str()
        .context("current executable path is not UTF-8")?;

    // On systemd < 256, `systemd-run --pty` will block indefinitely when
    // `Exec{StartPre,StopPost}` prints something.
    // See: https://github.com/systemd/systemd/issues/32916
    let sd_pty_workaround =
        !args.pipe && get_systemd_major_version().context("failed to get systemd version")? < 256;
    let sd_pty_workaround = sd_pty_workaround as u8;

    let conf_args = SysConfArgs {
        cpus: args.cpus.iter().copied().collect(),
        isolated: args.isolated || args.cpus.len() == 1,
        verbosity: args.verbosity,
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
                "--quiet",
                if args.pipe { "--pipe" } else { "--pty" },
                "--collect",
                "--wait",
                &format!("--unit={SERVICE_NAME}"),
                // It must be in a partition=root scope to set partition=root.
                "--slice=-.slice",
                "--description=Environment Controlled Benchmarks",
                "--service-type=exec",
                "--expand-environment=no",
                "--same-dir",
                &format!("--setenv={SETUP_SENTINEL}={setup_confs_json}"),
                &format!("--property=AllowedCPUs={allowed_cpus}"),
                &format!(
                    "--property=ExecStartPre=!@{self_exe} {SETUP_SENTINEL} {sd_pty_workaround} 1"
                ),
                &format!(
                    "--property=ExecStopPost=!@{self_exe} {SETUP_SENTINEL} {sd_pty_workaround} 0"
                ),
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
            args.verbosity.status(
                2,
                AnsiColors::Green,
                "WouldRun",
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

fn get_systemd_major_version() -> Result<u32> {
    let output = Command::new(SYSTEMD_RUN)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .arg("--version")
        .output()?;
    exit_ok(output.status)?;
    let output = String::from_utf8(output.stdout)?;
    // Format: "systemd 255 (255.4)\n+PAM +AUDIT -SELINUX [..]\n"
    let ver = output
        .split(' ')
        .nth(1)
        .context("invalid format")?
        .parse::<u32>()?;
    Ok(ver)
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
