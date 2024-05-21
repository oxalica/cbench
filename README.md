# cargo-cbench

cargo-cbench is a wrapper on native `cargo bench` with environment control for
more stable and reproducible benchmark results.
Currently only Linux/systemd is supported.

## Usages

1.  `cargo install --git https://github.com/oxalica/cargo-cbench.git`
1.  `cd` to your Rust project with [benches](cargo-bench).
1.  Use `cargo cbench` to run all benchmarks on CPU 1 with environment control.

    If extra cargo flags and/or bench flags are required, pass them as:

    `cargo cbench [CARGO_ARGS]... -- [BENCH_ARGS]...`

    More options can be viewed in `cargo cbench --help`.
1.  Binary `cbench` is also provided to execute arbitrary command in the
    controlled environment. You can use it for other non-Rust benchmark tools,
    eg:

    `cbench --setenv=PATH hyperfine true`

    Note: The target command will be run inside a systemd unit named
    'cbench.service' as the current user. It will be in a clean environment
    without inheriting from the current shell. You need to passthrough
    environment variables explicitly when necessary via `--setenv=ENV`.

## What it does

- `noaslr`: Disable [Address Space Layout Randomization (ASLR)][aslr] via
  [`/proc/sys/kernel/randomize_va_space`][randomize_va_space]
- `cpuset`: Pin the target process(es) on specific CPU(s) for exclusive access
  via [cgroup cpuset][cpuset].
- `noht`: Disable (set offline) CPU thread siblings of the CPU(s) used if
  hyper-threading is enabled, via [CPU hotplug][cpu-hotplug].
- `cpufreq`: Set power governor of target CPU(s) to 'performance' and disable
  adaptive turbo/boost, via [CPU Performance Scaling][cpufreq].

## Privileged operations

All settings mentioned above are privileged and machine global. To minimize the
impact and security risks, we leverage `systemd-run` privileged
`ExecStartPre=`/`ExecStopPost=` commands, thus only the environment setup and
reset will be executed with root privileges. Authentication is done by
`systemd-run` itself by default (via PolKit), or you can use `--use-sudo` to
use `sudo` instead.

Note that no matter whether `--use-sudo` is used, the program compilation (via
`cargo build`) and benchmark processes are always running as the current user.
Never add `sudo` to `cargo cbench` itself!

Environment modifications will be reverted after the program exits via systemd
`ExecStopPost=` command, which will do the clean up even if the target process
aborted unexpectedly (eg. by Ctrl-C). If they do not, please report a bug.

## Credit

Heavily motivated by [LLVM benchmarking tips][llvm-tips].

[cargo-bench]: https://doc.rust-lang.org/cargo/reference/profiles.html#bench
[aslr]: https://en.wikipedia.org/wiki/Address_space_layout_randomization
[randomize_va_space]: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space
[cpuset]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#cpuset-interface-files
[cpu-hotplug]: https://www.kernel.org/doc/html/latest/core-api/cpu_hotplug.html#using-cpu-hotplug
[cpufreq]: https://www.kernel.org/doc/html/latest/admin-guide/pm/cpufreq.html#policy-interface-in-sysfs
[llvm-tips]: https://llvm.org/docs/Benchmarking.html
