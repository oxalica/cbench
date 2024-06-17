use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio, Termination};

use anyhow::{Context, Result};
use cli::ExecArgs;
use itertools::Itertools;
use named_lock::NamedLock;
use owo_colors::AnsiColors;
use serde::{Deserialize, Serialize};

use crate::sysconf::{SysConf, SysConfArgs};

pub mod cli;
pub mod sysconf;

const SERVICE_NAME: &str = "cbench.service";
const SYSTEMD_RUN: &str = "systemd-run";

const SETUP_SENTINEL: &str = "__cbench_setup";

#[derive(Debug, Serialize, Deserialize)]
struct SetupArgs {
    systemd_pty_workaround: bool,
    sysconf_args: SysConfArgs,
    sysconfs: Vec<Box<dyn SysConf>>,
}

pub fn maybe_run_setup() {
    let mut args_iter = std::env::args_os();
    if !args_iter.next().is_some_and(|arg| arg == SETUP_SENTINEL) {
        return;
    }

    let is_enter = args_iter.next().unwrap() == "1";

    let args = std::env::var(SETUP_SENTINEL)
        .context("missing setup envvar")
        .and_then(|v| Ok(serde_json::from_str::<SetupArgs>(&v)?))
        .expect("setup args must be valid");

    if args.systemd_pty_workaround {
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

    let code = match main_setup(is_enter, &args) {
        Err(err) => {
            args.sysconf_args.verbosity.error(format_args!("{err:#}"));
            1
        }
        Ok(()) => 0,
    };
    std::process::exit(code);
}

/// Setup and cleanup of the benchmark environment.
/// NB. This is executed with full privileges as root.
fn main_setup(is_enter: bool, args: &SetupArgs) -> Result<()> {
    // Ignore termination signals.
    if let Err(err) = ctrlc::set_handler(|| {}) {
        args.sysconf_args
            .verbosity
            .error(format_args!("failed to set signal handlers: {err:#}"));
    }

    let run = |conf: &dyn SysConf| {
        if let Err(err) = conf.apply(is_enter, &args.sysconf_args) {
            args.sysconf_args.verbosity.error(format_args!("{err:#}"));
        }
    };

    let iter = args.sysconfs.iter().map(|s| &**s);
    if is_enter {
        iter.for_each(run);
    } else {
        iter.rev().for_each(run);
    }

    Ok(())
}

pub fn main_exec(
    args: &ExecArgs,
    exe_path: &impl AsRef<OsStr>,
    exe_args: &[impl AsRef<OsStr>],
) -> Result<()> {
    const LOCK_NAME: &str = "cargo-cbench.lock";

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
    let systemd_pty_workaround =
        !args.pipe && get_systemd_major_version().context("failed to get systemd version")? < 256;
    if systemd_pty_workaround {
        args.verbosity.warning(
            "detected systemd < 256 with buggy `--pty` behavior, \
            suppressing setup warnings and errors as workaround",
        );
    }

    let sysconf_args = SysConfArgs {
        cpus: args.cpus.clone(),
        isolated: args.isolated || args.cpus.len() == 1,
        verbosity: args.verbosity,
    };
    let sysconfs = sysconf::ALL_MODULES
        .iter()
        .filter(|(_, name, ..)| args.is_module_enabled(name))
        .map(|&(builder, ..)| builder(&sysconf_args))
        .collect::<Result<Vec<_>>>()?;
    let setup = SetupArgs {
        systemd_pty_workaround,
        sysconf_args,
        sysconfs,
    };
    let setup_json = serde_json::to_string(&setup).expect("serialization cannot fail");

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
            &format!("--setenv={SETUP_SENTINEL}={setup_json}"),
            &format!("--property=AllowedCPUs={}", args.cpus.iter().join(",")),
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
    cmd.arg(exe_path);
    cmd.args(exe_args);

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
