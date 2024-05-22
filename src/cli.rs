use std::collections::BTreeSet;
use std::ffi::OsString;

use itertools::Itertools;

/// Execute command in the controlled environment for benchmarks
#[derive(Debug, PartialEq, Eq, clap::Parser)]
pub struct Args {
    #[command(flatten)]
    pub exec_args: ExecArgs,

    /// The process to be run in controlled environment.
    pub command: OsString,

    /// Arguments for COMMAND
    #[arg(trailing_var_arg = true)]
    pub command_args: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq, clap::Args)]
pub struct ExecArgs {
    /// Use 'sudo' or SUDO_CMD to execute 'systemd-run' instead of running it as current user and
    /// use its own authentication method (PolKit)
    #[arg(long, name = "SUDO_CMD", num_args = 0..=1, require_equals = true, default_missing_value = "sudo")]
    pub use_sudo: Option<OsString>,

    /// Print what command will be executed without executing it, for debugging purpose.
    /// For `cargo-cbench` interface, the `cargo` command for compilation will still be executed.
    #[arg(long)]
    pub dry_run: bool,

    /// The exclusive CPUs used for cpuset. CPUS use the `AllowedCPUs=` syntax from
    /// systemd.resource-control(5). Note that CPU 0 and its siblings must not be
    /// used, since it's special and likely to be used for system tasks.
    #[arg(long, value_parser = parse_cpu_spec, default_value = "1", require_equals = true)]
    pub cpus: BTreeSet<u32>,

    /// Pass through environment variable ENV to the target process. The benchmark process will be
    /// run with systemd service's clean environment. Extra variables need to be explicitly pass in
    /// when necessary.
    #[arg(long, require_equals = true)]
    pub setenv: Vec<OsString>,
}

impl Default for ExecArgs {
    fn default() -> Self {
        Self {
            use_sudo: None,
            dry_run: false,
            cpus: <_>::from_iter([1]),
            setenv: Vec::new(),
        }
    }
}

fn parse_cpu_spec(s: &str) -> Result<BTreeSet<u32>, std::num::ParseIntError> {
    s.split(',')
        .map(|spec| {
            let (lhs, rhs) = spec.split_once('-').unwrap_or((spec, spec));
            Ok(lhs.parse()?..=rhs.parse()?)
        })
        .flatten_ok()
        .collect()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parse_basic() {
        Args::try_parse_from(["cbench"]).unwrap_err();

        assert_eq!(
            Args::try_parse_from(["cbench", "true"]).unwrap(),
            Args {
                exec_args: ExecArgs::default(),
                command: "true".into(),
                command_args: vec![],
            },
        );

        assert_eq!(
            Args::try_parse_from(["cbench", "--", "bash", "-c", "true"]).unwrap(),
            Args {
                exec_args: ExecArgs::default(),
                command: "bash".into(),
                command_args: vec!["-c".into(), "true".into()],
            },
        );

        assert_eq!(
            Args::try_parse_from(["cbench", "--dry-run", "--cpus=5,1-3", "env", "--", "-v"])
                .unwrap(),
            Args {
                exec_args: ExecArgs {
                    dry_run: true,
                    cpus: [1, 2, 3, 5].into_iter().collect(),
                    ..ExecArgs::default()
                },
                command: "env".into(),
                command_args: vec!["-v".into()],
            },
        );
    }

    #[test]
    fn parse_use_sudo() {
        assert_eq!(
            Args::try_parse_from(["cbench", "--use-sudo", "true"]).unwrap(),
            Args {
                exec_args: ExecArgs {
                    use_sudo: Some("sudo".into()),
                    ..ExecArgs::default()
                },
                command: "true".into(),
                command_args: vec![],
            },
        );

        assert_eq!(
            Args::try_parse_from(["cbench", "--use-sudo=doas", "true"]).unwrap(),
            Args {
                exec_args: ExecArgs {
                    use_sudo: Some("doas".into()),
                    ..ExecArgs::default()
                },
                command: "true".into(),
                command_args: vec![],
            },
        );

        assert_eq!(
            Args::try_parse_from(["cbench", "--use-sudo", "doas", "true"]).unwrap(),
            Args {
                exec_args: ExecArgs {
                    use_sudo: Some("sudo".into()),
                    ..ExecArgs::default()
                },
                command: "doas".into(),
                command_args: vec!["true".into()],
            },
        );
    }
}
