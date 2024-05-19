use std::convert::Infallible;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

use anyhow::{ensure, Context, Result};
use cargo_metadata::Message;
use itertools::Itertools;
use named_lock::NamedLock;
use owo_colors::OwoColorize;

const ASLR_CTL: &str = "/proc/sys/kernel/randomize_va_space";
const CGROUP_CPUSET_PARTITION_CTL: &str = "/sys/fs/cgroup/cbench.service/cpuset.cpus.partition";
const SERVICE_NAME: &str = "cbench.service";
const SYSTEMD_RUN: &str = "systemd-run";

const SETUP_ARG0: &str = "__setup";

#[derive(Debug, Default)]
struct Args {
    help: bool,
    use_sudo: Option<OsString>,
    dry_run: bool,
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

fn main() -> ExitCode {
    let mut args_iter = std::env::args_os();
    let argv0 = PathBuf::from(args_iter.next().expect("missing argv0"));
    let argv0 = argv0.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    let ret = if argv0 == SETUP_ARG0 {
        let args = args_iter.map(|s| s.into_string().unwrap()).collect();
        main_setup(args)
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
                main_exec(&benches, &args.verbatim_args, args.use_sudo, args.dry_run)
            })
        } else {
            args.rest_args.extend(args.verbatim_args);
            main_exec(
                &[&args.subcommand],
                &args.rest_args,
                args.use_sudo,
                args.dry_run,
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
fn main_setup(args: Vec<String>) -> Result<()> {
    // Ignore termination signals.
    ctrlc::set_handler(|| {})?;

    let aslr_state = &args[0];
    let disable_sibling_cpus = args[1] == "1";
    let sibling_cpus = args[2]
        .split(',')
        .skip_while(|s| s.is_empty())
        .map(|s| s.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    if !aslr_state.is_empty() {
        assert_eq!(aslr_state.len(), 1);
        fs::write(ASLR_CTL, aslr_state)
            .with_context(|| format!("failed to set ASLR state to {aslr_state:?}"))?;
    }

    let set_cpuset_root = args[1] == "1";
    if set_cpuset_root {
        fs::write(CGROUP_CPUSET_PARTITION_CTL, "root")
            .context("failed to set cpuset partition to root")?;
    }

    let (data, op) = if disable_sibling_cpus {
        ("0", "disable")
    } else {
        ("1", "enable")
    };
    for &cpu in &sibling_cpus {
        fs::write(format!("/sys/devices/system/cpu/cpu{cpu}/online"), data)
            .with_context(|| format!("failed to {op} CPU {cpu}"))?;
    }

    Ok(())
}

fn main_exec(
    bench_exes: &[impl AsRef<OsStr>],
    bench_args: &[impl AsRef<OsStr>],
    sudo_cmd: Option<impl AsRef<OsStr>>,
    dry_run: bool,
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

    let mut prev_aslr = fs::read_to_string(ASLR_CTL).context("failed to get current ASLR state")?;
    if prev_aslr.ends_with('\n') {
        prev_aslr.pop();
    }
    ensure!(
        !prev_aslr.is_empty() && prev_aslr.chars().all(|c| c.is_ascii_digit()),
        "invalid ASLR state: {prev_aslr:?}"
    );
    let (new_aslr, prev_aslr) = if prev_aslr != "0" {
        ("0", prev_aslr)
    } else {
        eprintln!(
            "{}: ASLR is already disabled, skipped setting",
            "warning".yellow().bold(),
        );
        ("", String::new())
    };

    // TODO: Configurable.
    let mut cpus = vec![1, 2];
    cpus.sort_unstable();
    cpus.dedup();
    let mut sibling_cpus = Vec::new();
    for &cpu in &cpus {
        let siblings = fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ))
        .context("failed to read CPU thread siblings")?;
        for sibling in siblings.trim_end().split(',') {
            let sibling = sibling
                .parse::<u32>()
                .with_context(|| format!("failed to parse CPU thread siblings: {siblings}"))?;
            if sibling != cpu {
                sibling_cpus.push(sibling);
            }
        }
    }
    sibling_cpus.sort_unstable();
    sibling_cpus.dedup();
    ensure!(cpus != *sibling_cpus, "all allowed CPUs are siblings");
    let allowed_cpus = cpus.iter().join(",");
    let sibling_cpus = sibling_cpus.iter().join(",");

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
                "--description=Environment Controled Benchmarks",
                "--service-type=exec",
                "--expand-environment=no",
                &format!("--uid={}", nix::unistd::getuid().as_raw()),
                &format!("--gid={}", nix::unistd::getgid().as_raw()),
                "--same-dir",
                &format!("--property=AllowedCPUs={allowed_cpus}"),
                &format!(
                    "--property=ExecStartPre=!@{self_exe} {SETUP_ARG0} '{new_aslr}' 1 '{sibling_cpus}'"
                ),
                &format!(
                    "--property=ExecStopPost=!@{self_exe} {SETUP_ARG0} '{prev_aslr}' 0 '{sibling_cpus}'"
                ),
            ]);
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