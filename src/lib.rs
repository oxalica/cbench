use std::convert::Infallible;
use std::ffi::{OsStr, OsString};
use std::io::BufReader;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

use anyhow::{ensure, Context, Result};
use cargo_metadata::Message;
use itertools::Itertools;
use named_lock::NamedLock;
use owo_colors::OwoColorize;

use crate::sysconf::SysConf;

mod sysconf;

const SERVICE_NAME: &str = "cbench.service";
const SYSTEMD_RUN: &str = "systemd-run";

const SETUP_SENTINEL: &str = "__cbench_setup";

#[derive(Debug, Default)]
struct Args {
    help: bool,
    use_sudo: Option<OsString>,
    dry_run: bool,
    cpus: Vec<u32>,
    setenv: Vec<String>,
    subcommand: OsString,
    rest_args: Vec<OsString>,
    verbatim_args: Vec<OsString>,
}

impl Args {
    fn parse(mut args: Vec<OsString>) -> Result<Self> {
        let mut this = Self::default();
        if let Some(pos) = args.iter().position(|s| s == "--") {
            this.verbatim_args = args.split_off(pos + 1);
            args.pop();
        }
        let mut args = pico_args::Arguments::from_vec(args);
        this.help = args.contains("--help");
        this.dry_run = args.contains("--dry-run");
        this.use_sudo = if args.contains("--use-sudo") {
            Some("sudo".into())
        } else {
            args.opt_value_from_os_str("--use-sudo", |s| Ok::<_, Infallible>(s.to_owned()))?
        };
        this.cpus = args
            .opt_value_from_fn("--cpus", |arg| {
                arg.split(',')
                    .map(|spec| {
                        let (start, end) = match spec.split_once('-') {
                            Some((start, end)) => (start.parse()?, Some(end.parse()?)),
                            None => (spec.parse::<u32>()?, None),
                        };
                        Ok(start..=end.unwrap_or(start))
                    })
                    .flatten_ok()
                    .collect::<Result<Vec<_>>>()
            })?
            .unwrap_or_else(|| vec![1]);
        // NB. `values_from_os_str` does not support eq-separator.
        this.setenv = args.values_from_str("--setenv")?;

        this.rest_args = args.finish();
        let subcmd = this
            .rest_args
            .first()
            .context("missing command")?
            .to_string_lossy();
        ensure!(!subcmd.starts_with('-'), "invalid option: {subcmd}");
        this.subcommand = this.rest_args.remove(0);
        Ok(this)
    }
}

pub fn main() -> ExitCode {
    let mut args_iter = std::env::args_os();
    let argv0 = PathBuf::from(args_iter.next().expect("missing argv0"));
    let argv0 = argv0.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    let ret = if argv0 == SETUP_SENTINEL {
        let (is_enter, confs) = (|| -> Result<(bool, Vec<Box<dyn SysConf>>)> {
            let is_enter = args_iter.next().context("missing argv1")? == "1";
            let args = std::env::var(SETUP_SENTINEL).context("missing setup envvar")?;
            Ok((is_enter, serde_json::from_str(&args)?))
        })()
        .expect("setup args must be valid");
        main_setup(is_enter, &confs)
    } else {
        let mut args = match Args::parse(args_iter.collect()) {
            Ok(args) if !args.help => args,
            Ok(_) => {
                print_help();
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("{}: {err}", "error".red().bold());
                print_help();
                return ExitCode::FAILURE;
            }
        };

        if argv0 == "cargo-cbench" && args.subcommand == "cbench" {
            args.verbatim_args.insert(0, "--bench".into());
            let mut benches = Vec::new();
            main_build(&args.rest_args, &mut benches).and_then(|()| {
                main_exec(
                    &benches,
                    &args.verbatim_args,
                    args.use_sudo,
                    args.dry_run,
                    args.cpus,
                    &args.setenv,
                )
            })
        } else {
            args.rest_args.extend(args.verbatim_args);
            main_exec(
                &[&args.subcommand],
                &args.rest_args,
                args.use_sudo,
                args.dry_run,
                args.cpus,
                &args.setenv,
            )
        }
    };

    match ret {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{}: {:#}", "error".red().bold(), err);
            if let Some(ExitStatusError(st)) = err.downcast_ref() {
                ExitCode::from((st.code().unwrap_or(1) as u8).max(1))
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn print_help() {
    println!(
        "\
Environment control for benchmarks

USAGE: cargo cbench [OPTIONS]... [CARGO_ARGS]...
       cargo cbench [OPTIONS]... [CARGO_ARGS]... -- [BENCH_ARGS]...
       cbench [OPTIONS]... COMMAND [--] [COMMAND_ARGS]...

Options:
  --use-sudo[=<SUDO_CMD>]   Use 'sudo' or SUDO_CMD to execute 'systemd-run'
                            instead of running it as current user and use its
                            own authentication method (polkit, by default)
  --cpus=SPECS
  --cpus SPECS              Run benchmarks on specific CPUs exclusively. SPECS
                            use the `AllowedCPUs=` syntax from
                            systemd.resource-control(5). Default: `1`.
                            Note that CPU 0 and its siblings must not be used,
                            since it's likely used for system tasks.
  --setenv=ENV              Pass through environment variable ENV to the
                            target process. By default the process will be run
                            with systemd service's lcean default environment.
                            Extra variables need to be explicitly pass in when
                            necessary.
"
    );
}

fn main_build(cargo_args: &[impl AsRef<OsStr>], benches: &mut Vec<PathBuf>) -> Result<()> {
    let mut child = Command::new("cargo")
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
    Ok(())
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

// TODO: Struct argument.
fn main_exec(
    bench_exes: &[impl AsRef<OsStr>],
    bench_args: &[impl AsRef<OsStr>],
    sudo_cmd: Option<impl AsRef<OsStr>>,
    dry_run: bool,
    mut cpus: Vec<u32>,
    envs: &[impl AsRef<OsStr>],
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

    cpus.sort_unstable();
    cpus.dedup();

    let confs = [
        Box::new(sysconf::Aslr::init()?) as Box<dyn SysConf>,
        Box::new(sysconf::CpusetExclusive),
        Box::new(sysconf::CpuFreq::init(&cpus)?),
        Box::new(sysconf::DisableSiblingCpus::init(&cpus)?),
    ];
    let setup_confs_json = serde_json::to_string(&confs).expect("serialization cannot fail");
    let allowed_cpus = cpus.iter().join(",");

    for exe in bench_exes {
        let mut cmd = match &sudo_cmd {
            None => Command::new(SYSTEMD_RUN),
            Some(sudo) => Command::new(sudo),
        };
        cmd.args(sudo_cmd.is_some().then_some(SYSTEMD_RUN))
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
                &format!("--uid={}", nix::unistd::getuid().as_raw()),
                &format!("--gid={}", nix::unistd::getgid().as_raw()),
                "--same-dir",
                &format!("--setenv={SETUP_SENTINEL}={setup_confs_json}"),
                &format!("--property=AllowedCPUs={allowed_cpus}"),
                &format!("--property=ExecStartPre=!@{self_exe} {SETUP_SENTINEL} 1"),
                &format!("--property=ExecStopPost=!@{self_exe} {SETUP_SENTINEL} 0"),
            ]);
        for env in envs {
            let mut arg = OsString::from("--setenv=");
            arg.push(env);
            cmd.arg(arg);
        }

        cmd.arg("--");
        cmd.arg(exe.as_ref());
        cmd.args(bench_args);

        if dry_run {
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
#[derive(Debug)]
struct ExitStatusError(ExitStatus);
impl std::fmt::Display for ExitStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "process exited unsuccessfully: {}", self.0)
    }
}
impl std::error::Error for ExitStatusError {}
fn exit_ok(status: ExitStatus) -> Result<(), ExitStatusError> {
    status
        .success()
        .then_some(())
        .ok_or(ExitStatusError(status))
}
