# [cargo-]cbench

Environment control for benchmarks on Linux/systemd, reducing external noise
from benchmark results.

`cbench` can be used to run any programs. `cargo-cbench` is a wrapper giving a
`cargo bench`-like interface for running [cargo benches][cargo-bench] conveniently.

## Installation

`cargo install --git https://github.com/oxalica/cbench.git`

## Usage

For Rust projects with cargo benches, simply replace `cargo bench` with
`cargo cbench`:

`cargo cbench`

This will setup the environment and tweak system configurables (see
[the next section](#what-it-does)), run all cargo benchmarks in the current
project, and finally revert changes to the original state.

It will only allocate a single *exclusive* CPU for the benchmark. If your
program is multi-threaded, you can allocate more by:

`cargo cbench --cpus=1-2`

Cargo flags and bench program flags can be passed using the same syntax:

`cargo cbench --bench=bench1 --features=feat1 -- --exact foo`

For other benchmarking frameworks, run `cbench` following by the command:

`cbench hyperfine /some/benchee`

By default, the target command will be run inside a systemd unit named
'cbench.service' as the current user. It will be in a clean environment
without inheriting from the current shell. If your command relies on some
environment variables, you need to pass them explicitly via `--setenv=ENV` or
`--setenv=ENV=VALUE`.

More control arguments can be seen in `cbench --help`.

## What it does

- `noaslr`: Disable [Address Space Layout Randomization (ASLR)][aslr] via
  [`/proc/sys/kernel/randomize_va_space`][randomize_va_space]
- `cpuset`: Pin the target process' cgroup on specific CPU(s) for exclusive use
  via [cgroup cpuset][cpuset].
- `noht`: Disable (set offline) CPU thread siblings of the CPU(s) used if
  hyper-threading is enabled, via [CPU hotplug][cpu-hotplug].
- `cpufreq`: Set power governor of target CPU(s) to 'performance' and disable
  adaptive turbo/boost, via [CPU Performance Scaling][cpufreq].
- `noirq`: Mask used CPU(s) from [IRQ affinity][irq-affinity].

These control modules can be enabled or disabled individually via `--with=` or
`--without=`.

## What it does NOT

- We don't do benchmarks, but we setup environment and tunables for benchmark
  programs to do benchmarks more reliably. It's expected to be used together
  with benchmark frameworks/programs like [`criterion`][criterion] or
  [`hyperfine`][hyperfine].

- Environment control does not make programs run faster, but typically in
  opposite, because we disable frequency boost by default. Our goal is
  consistency rather than performance.

- We reduce external noise from tainting the benchmark results. But we cannot
  magically stabilize it from internal biases. Benchee may still be unstable
  under different memory (heap and stack) layout caused by environment
  variables or "being lucky" on program initialization, producing a
  seemingly random systemic bias through multiple runs. You need to carefully
  write your benchee program to reduce this effect.

  See [stabilizer] for more information.

## Privileged operations

All settings mentioned above are privileged and machine global. To minimize the
impact and security risks, we leverage `systemd-run` privileged
`ExecStartPre=`/`ExecStopPost=` commands, thus only the environment setup and
reset will be executed with root privileges. Authentication is done by
`systemd-run` itself by default (via PolKit), or you can use `--use-sudo` to
use `sudo` instead.

Note that no matter whether `--use-sudo` is used, the program compilation (via
`cargo build`) and benchmark processes are always running as the current user.
Never add `sudo` to `cargo cbench` itself! Even if you really want to run the
target artifact/command as `root` because, say you are running `perf stat
--all-kernel`, use the option `--root` for it.

Environment modifications will be reverted after the program exits via systemd
`ExecStopPost=` command, which will do the clean up even if the target process
aborted unexpectedly (eg. by Ctrl-C). If they do not, please report a bug.

## Credit

- Heavily motivated by [LLVM benchmarking tips][llvm-tips].
- Thank [QuarticCat@github](https://github.com/QuarticCat) for turbo/boost control tips.
- Thank [PeterCxy@github](https://github.com/PeterCxy) for IRQ control tips.

[cargo-bench]: https://doc.rust-lang.org/cargo/reference/profiles.html#bench
[criterion]: https://github.com/bheisler/criterion.rs
[hyperfine]: https://github.com/sharkdp/hyperfine
[aslr]: https://en.wikipedia.org/wiki/Address_space_layout_randomization
[randomize_va_space]: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space
[cpuset]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#cpuset-interface-files
[cpu-hotplug]: https://www.kernel.org/doc/html/latest/core-api/cpu_hotplug.html#using-cpu-hotplug
[cpufreq]: https://www.kernel.org/doc/html/latest/admin-guide/pm/cpufreq.html#policy-interface-in-sysfs
[irq-affinity]: https://www.kernel.org/doc/html/latest/core-api/irq/irq-affinity.html
[stabilizer]: https://github.com/ccurtsinger/stabilizer
[llvm-tips]: https://llvm.org/docs/Benchmarking.html
