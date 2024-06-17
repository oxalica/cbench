use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;

use clap::builder::PossibleValue;
use itertools::Itertools;
use owo_colors::{AnsiColors, OwoColorize};
use serde::{Deserialize, Serialize};

/// Execute command in the controlled environment for benchmarks
#[derive(Debug, PartialEq, Eq, clap::Parser)]
#[command(version, about)]
#[command(after_long_help = "\
Copyright (C) 2024  Oxalica

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
")]
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
    /// Behavior control options. ///

    /// Print what command will be executed without executing it, for debugging purpose.
    /// For `cargo-cbench` interface, the `cargo` command for compilation will still be executed.
    #[arg(long)]
    pub dry_run: bool,

    #[command(flatten)]
    pub verbosity: Verbosity,

    /// Systemd-run options. ///

    /// Use 'sudo' or SUDO_CMD to execute 'systemd-run' instead of running it as current user and
    /// use its own authentication method (PolKit)
    #[arg(long, name = "SUDO_CMD", num_args = 0..=1, require_equals = true, default_missing_value = "sudo")]
    pub use_sudo: Option<OsString>,

    /// Run the target process under `root` instead of current user and group.
    #[arg(long)]
    pub root: bool,

    /// Use `--pipe` instead of `--pty` for `systemd-run`.
    /// This should only be used in scripts. See systemd-run(1) for differences.
    #[arg(long)]
    pub pipe: bool,

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

    /// Sysconf options. ///

    /// Only enable specific environment control modules. By default all supported modules are
    /// enabled. Accept one or more strings separated by `,`.
    #[arg(
        long,
        require_equals = true,
        value_delimiter = ',',
        value_parser = sysconf_values(),
        default_values_os_t = default_sysconfs(),
        // Duplicates with possible values.
        hide_default_value = true,
    )]
    pub with: Vec<String>,

    /// Exclude specific environment control modules from default. By default all supported modules
    /// are enabled. The syntax is the same as `--with`.
    #[arg(
        long,
        require_equals = true,
        conflicts_with = "with",
        value_delimiter = ',',
        value_parser = sysconf_values(),
        // Duplicates.
        hide_default_value = true,
        hide_possible_values = true,
    )]
    pub without: Option<Vec<String>>,

    /// Disable load balancing on used CPU(s). Only effective when `cpuset` module is enabled.
    /// When only a single CPU is used, this option is implied.
    /// It corresponds with `isolated` value for `cpuset.cpus.partition`.
    #[arg(long)]
    pub isolated: bool,
}

impl ExecArgs {
    pub fn is_module_enabled(&self, name: &str) -> bool {
        if let Some(without) = &self.without {
            return without.iter().all(|s| s != name);
        }
        self.with.iter().any(|s| s == name)
    }
}

fn sysconf_values() -> Vec<PossibleValue> {
    crate::sysconf::ALL_MODULES
        .iter()
        .map(|(_ctor, name, help)| PossibleValue::new(name).help(help))
        .collect()
}

fn default_sysconfs() -> Vec<String> {
    crate::sysconf::ALL_MODULES
        .iter()
        .map(|(_ctor, name, ..)| name.to_string())
        .collect()
}

impl Default for ExecArgs {
    fn default() -> Self {
        Self {
            dry_run: false,
            verbosity: Verbosity::default(),
            use_sudo: None,
            root: false,
            pipe: false,
            cpus: <_>::from_iter([1]),
            setenv: Vec::new(),
            with: default_sysconfs(),
            without: None,
            isolated: false,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::Args)]
pub struct Verbosity {
    /// More verbose output.
    #[arg(
        long,
        short,
        action = clap::ArgAction::Count,
    )]
    pub verbose: u8,

    /// More quiet output.
    #[arg(
        long,
        short,
        action = clap::ArgAction::Count,
        conflicts_with = "verbose",
    )]
    pub quiet: u8,
}

impl Verbosity {
    pub fn iter_flags(&self) -> impl Iterator<Item = &'static str> {
        std::iter::repeat("-v")
            .take(self.verbose.into())
            .chain(std::iter::repeat("-q").take(self.quiet.into()))
    }

    pub fn error(&self, f: impl fmt::Display) {
        self.println(2, format_args!("{}: {}", "error".bold().red(), f));
    }

    pub fn warning(&self, f: impl fmt::Display) {
        self.println(1, format_args!("{}: {}", "warning".bold().yellow(), f));
    }

    pub fn note(&self, f: impl fmt::Display) {
        self.println(0, format_args!("{}: {}", "note".bold().cyan(), f));
    }

    pub fn status(&self, severity: i8, color: AnsiColors, header: &str, f: impl fmt::Display) {
        let threshold = self.quiet as i8 - self.verbose as i8;
        if threshold < severity {
            self.println(
                severity,
                format_args!("{:>12} {}", header.bold().color(color), f),
            );
        }
    }

    fn println(&self, severity: i8, f: impl fmt::Display) {
        let threshold = self.quiet as i8 - self.verbose as i8;
        if threshold < severity {
            eprintln!("{f}");
        }
    }
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
