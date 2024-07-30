use std::collections::BTreeSet;
use std::io::{ErrorKind, Write};

use anyhow::{bail, ensure, Context, Result};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::cli::Verbosity;
use crate::{parse_cpu_spec, SERVICE_NAME};

/// Read from a virtual file and chomp away the trailing newline.
fn read_vfile(path: &str) -> Result<String> {
    let mut s = std::fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    if s.ends_with('\n') {
        s.pop();
    }
    Ok(s)
}

/// Write to a virtual file within a single syscall.
fn write_vfile(path: &str, content: &str) -> Result<()> {
    std::fs::File::options()
        .write(true)
        .open(path)
        .map_err(Into::into)
        .and_then(|mut f| match f.write(content.as_bytes()) {
            Ok(n) if n == content.len() => Ok(()),
            Ok(n) => bail!("partial write of {n} bytes"),
            Err(err) => Err(err.into()),
        })
        .with_context(|| format!("failed to write {content:?} to {path}"))
}

macro_rules! modules {
    ($($ty:ident),* $(,)?) => { [$(($ty::init_boxed, $ty::NAME, $ty::HELP),)*] }
}

type ModuleBuilder = fn(&SysConfArgs) -> Result<Box<dyn SysConf>>;

#[rustfmt::skip]
pub static ALL_MODULES: &[(ModuleBuilder, &str, &str)] = &modules![
    NoAslr,
    CpusetExclusive,
    CpuFreq,
    NoIrq,
    NoHyperThreading,
];

#[derive(Debug, Serialize, Deserialize)]
pub struct SysConfArgs {
    pub cpus: BTreeSet<u32>,
    pub isolated: bool,
    pub verbosity: Verbosity,
}

/// Extensible system configuration change unit.
#[typetag::serde(tag = "type")]
pub trait SysConf: std::fmt::Debug + 'static {
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized;

    fn init_boxed(args: &SysConfArgs) -> Result<Box<dyn SysConf>>
    where
        Self: Sized,
    {
        Self::init(args).map(|this| Box::new(this) as _)
    }

    fn apply(&self, is_enter: bool, args: &SysConfArgs) -> Result<()>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoAslr {
    prev: Option<String>,
}

impl NoAslr {
    const NAME: &'static str = "noaslr";
    const HELP: &'static str = "Disable Address Space Layout Randomization (ASLR)";

    const CTL_PATH: &'static str = "/proc/sys/kernel/randomize_va_space";
}

#[typetag::serde]
impl SysConf for NoAslr {
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let st = read_vfile(Self::CTL_PATH)?;
        let st = if st == "0" {
            args.verbosity.warning("ASLR is already disabled");
            None
        } else {
            Some(st)
        };
        Ok(Self { prev: st })
    }

    fn apply(&self, is_enter: bool, _: &SysConfArgs) -> Result<()> {
        let Some(prev) = &self.prev else {
            return Ok(());
        };
        let v = if is_enter { "0" } else { prev };
        write_vfile(Self::CTL_PATH, v)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpusetExclusive;

impl CpusetExclusive {
    const NAME: &'static str = "cpuset";
    const HELP: &'static str = "Pin the process' cgroup on specific CPU(s) for exclusive use";
}

#[typetag::serde]
impl SysConf for CpusetExclusive {
    fn init(_: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn apply(&self, is_enter: bool, args: &SysConfArgs) -> Result<()> {
        if is_enter {
            let value = if args.isolated { "isolated" } else { "root" };
            write_vfile(
                &format!("/sys/fs/cgroup/{SERVICE_NAME}/cpuset.cpus.partition"),
                value,
            )
        } else {
            // The whole cgroup will be removed by systemd after the service exit.
            // Nothing need to be done here.
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoHyperThreading {
    sibling_cpus: Vec<u32>,
}

impl NoHyperThreading {
    fn cpu_online_path(cpu: u32) -> String {
        format!("/sys/devices/system/cpu/cpu{cpu}/online")
    }
}

impl NoHyperThreading {
    const NAME: &'static str = "noht";
    const HELP: &'static str = "Disable (set offline) CPU thread siblings of the CPU(s) used if hyper-threading is enabled";
}

#[typetag::serde]
impl SysConf for NoHyperThreading {
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let mut sibling_cpus = Vec::new();
        for &cpu in &args.cpus {
            let sibling_path =
                format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
            let siblings_str = read_vfile(&sibling_path)?;
            let siblings = parse_cpu_spec(&siblings_str).with_context(|| {
                format!("failed to parse siblings of CPU {cpu}: {siblings_str:?}")
            })?;
            for &sibling in &siblings {
                if sibling != cpu {
                    ensure!(
                        !args.cpus.contains(&sibling),
                        "CPU {cpu} and {sibling} are siblings, only one can be specified",
                    );
                    sibling_cpus.push(sibling);
                }
            }
        }
        sibling_cpus.sort_unstable();
        sibling_cpus.dedup();
        ensure!(
            !args.cpus.contains(&0) && !sibling_cpus.contains(&0),
            "CPU 0 and its siblints are not allowed for exclusive use",
        );
        Ok(Self { sibling_cpus })
    }

    fn apply(&self, is_enter: bool, _: &SysConfArgs) -> Result<()> {
        let v = if is_enter { "0" } else { "1" };
        for &cpu in &self.sibling_cpus {
            write_vfile(&Self::cpu_online_path(cpu), v)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpuFreq {
    prev_governors: Vec<(u32, String)>,
    prev_boost: CpuBoost,
}

#[derive(Debug, Serialize, Deserialize)]
enum CpuBoost {
    Ignore,
    IntelNoTurbo(String),
    CpufreqBoost(String),
    /// Previous `energy_performance_available_preferences` for ALL cpus.
    ///
    /// When `amd_pstate=active`, we cannot easily disable turbo because cpufreq is fully
    /// controlled by the firmware. We hereby need to set it to `passive` mode and disable `boost`.
    /// In reset phase, we revert it back to `active` mode and recover settings according to this.
    AmdPstateActivePrefs(Vec<(u32, String)>),
}

impl CpuFreq {
    const NAME: &'static str = "cpufreq";
    const HELP: &'static str =
        "Set power governor of target CPU(s) to 'performance' and disable adaptive turbo/boost";

    const INTEL_NO_TURBO_PATH: &'static str = "/sys/devices/system/cpu/intel_pstate/no_turbo";
    const CPUFREQ_BOOST_PATH: &'static str = "/sys/devices/system/cpu/cpufreq/boost";
    const AMD_PSTATE_STATUS_PATH: &'static str = "/sys/devices/system/cpu/amd_pstate/status";

    fn get_boost(args: &SysConfArgs) -> Result<CpuBoost> {
        match read_vfile(Self::INTEL_NO_TURBO_PATH) {
            Ok(s) if s != "1" => return Ok(CpuBoost::IntelNoTurbo(s)),
            Ok(_) => {
                args.verbosity
                    .warning("Intel CPU turbo is already disabled");
                return Ok(CpuBoost::Ignore);
            }
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == ErrorKind::NotFound) => {}
            Err(err) => return Err(err),
        }

        match read_vfile(Self::CPUFREQ_BOOST_PATH) {
            Ok(s) if s != "0" => return Ok(CpuBoost::CpufreqBoost(s)),
            Ok(_) => {
                args.verbosity.warning("cpufreq boost is already disabled");
                return Ok(CpuBoost::Ignore);
            }
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == ErrorKind::NotFound) => {}
            Err(err) => return Err(err),
        }

        if read_vfile(Self::AMD_PSTATE_STATUS_PATH).is_ok_and(|s| s == "active") {
            // amd_pstate=active detected.
            let mut prev_prefs = std::fs::read_dir("/sys/devices/system/cpu")?
                .map(|ent| {
                    let ent = ent?;
                    if !ent.file_type()?.is_dir() {
                        return Ok(None);
                    }
                    let Some(cpu) = ent
                        .file_name()
                        .to_str()
                        .and_then(|s| s.strip_prefix("cpu")?.parse::<u32>().ok())
                    else {
                        return Ok(None);
                    };
                    match read_vfile(&Self::epp_path(cpu)) {
                        Ok(pref) => Ok(Some((cpu, pref))),
                        // The file does not exist when CPU's offline. Skip in that case.
                        Err(err)
                            if err.downcast_ref::<std::io::Error>().unwrap().kind()
                                == ErrorKind::NotFound
                                && read_vfile(&NoHyperThreading::cpu_online_path(cpu))
                                    .is_ok_and(|s| s == "0") =>
                        {
                            Ok(None)
                        }
                        Err(err) => Err(err),
                    }
                })
                .filter_map(|ret| ret.transpose())
                .collect::<Result<Vec<_>>>()
                .context(
                    "failed to read energy_performance_preference for amd_pstate active mode",
                )?;
            prev_prefs.sort_unstable_by_key(|(cpu, _)| *cpu);
            return Ok(CpuBoost::AmdPstateActivePrefs(prev_prefs));
        }

        args.verbosity
            .warning("unsupported CPU and/or cpufreq driver, skip disabling turbo/boost");
        Ok(CpuBoost::Ignore)
    }

    fn governor_path(cpu: u32) -> String {
        format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
    }

    fn epp_path(cpu: u32) -> String {
        format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/energy_performance_preference")
    }

    fn set_governors(&self, new_gov: Option<&str>) -> Result<()> {
        for (cpu, prev_gov) in &self.prev_governors {
            let gov = new_gov.unwrap_or(prev_gov);
            write_vfile(&Self::governor_path(*cpu), gov)?;
        }
        Ok(())
    }
}

#[typetag::serde]
impl SysConf for CpuFreq {
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let prev_governors = args
            .cpus
            .iter()
            .map(|&cpu| {
                let gov = read_vfile(&Self::governor_path(cpu))?;
                Ok((cpu, gov))
            })
            .collect::<Result<Vec<_>>>()?;
        let prev_turbo = Self::get_boost(args)?;
        Ok(Self {
            prev_governors,
            prev_boost: prev_turbo,
        })
    }

    fn apply(&self, is_enter: bool, _: &SysConfArgs) -> Result<()> {
        // NB. This may change driver state of amd_pstate which resets governors.
        // Thus it always need to be done before setting governors.
        match &self.prev_boost {
            CpuBoost::Ignore => {}
            CpuBoost::IntelNoTurbo(prev) => {
                let v = if is_enter { "1" } else { prev };
                write_vfile(Self::INTEL_NO_TURBO_PATH, v)?
            }
            CpuBoost::CpufreqBoost(prev) => {
                let v = if is_enter { "0" } else { prev };
                write_vfile(Self::CPUFREQ_BOOST_PATH, v)?;
            }
            CpuBoost::AmdPstateActivePrefs(prefs) => {
                if is_enter {
                    write_vfile(Self::AMD_PSTATE_STATUS_PATH, "passive")?;
                    write_vfile(Self::CPUFREQ_BOOST_PATH, "0")?
                } else {
                    write_vfile(Self::AMD_PSTATE_STATUS_PATH, "active")?;
                    for (cpu, pref) in prefs {
                        write_vfile(&Self::epp_path(*cpu), pref)?;
                    }
                }
            }
        }
        self.set_governors(is_enter.then_some("performance"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoIrq {
    default_affinity: Option<(String, String)>,
    irq_affinity: Vec<(u32, String, String)>,
}

impl NoIrq {
    const NAME: &'static str = "noirq";
    const HELP: &'static str = "Mask used CPU(s) from IRQ affinity";

    const DEFAULT_AFFINITY_PATH: &'static str = "/proc/irq/default_smp_affinity";

    fn irq_smp_affinity_path(irq: u32) -> String {
        format!("/proc/irq/{irq}/smp_affinity")
    }

    fn calc_masks_change(args: &SysConfArgs, path: &str) -> Result<Option<(String, String)>> {
        let prev_masks = read_vfile(path)?;

        let mut masks = prev_masks
            .split(',')
            .map(|seg| u32::from_str_radix(seg, 16))
            .collect::<Result<Vec<_>, _>>()?;

        // Mask off every CPU used by us.
        let mut changed = false;
        for &cpu in &args.cpus {
            // TODO: Is this using machine endianness?
            let (idx, bit) = (cpu as usize / 32, 1u32 << (cpu % 32));
            if masks[idx] & bit != 0 {
                changed = true;
                masks[idx] ^= bit;
            }
        }
        // Skip uneffected IRQs.
        if !changed {
            return Ok(None);
        }

        // Do not leave it empty, it would be invalid. CPU 0 must not be used by us.
        if masks.iter().all(|&m| m == 0) {
            masks[0] = 1;
        }

        let new_masks = masks
            .iter()
            .format_with(",", |&m, f| f(&format_args!("{m:x}")))
            .to_string();
        Ok(Some((prev_masks, new_masks)))
    }
}

#[typetag::serde]
impl SysConf for NoIrq {
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let default_affinity = Self::calc_masks_change(args, Self::DEFAULT_AFFINITY_PATH)
            .context("failed to read default_smp_affinity")?;

        let mut irq_affinity = Vec::new();
        for ent in std::fs::read_dir("/proc/irq").context("failed to list /proc/irq")? {
            let ent = ent.context("failed to list /proc/irq")?;
            if !ent.file_type()?.is_dir() {
                continue;
            }
            let Some(irq) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };

            let change = Self::calc_masks_change(args, &Self::irq_smp_affinity_path(irq))
                .with_context(|| format!("failed to read smp_affinity of IRQ {irq}"))?;
            if let Some((prev, new)) = change {
                irq_affinity.push((irq, prev, new));
            }
        }
        irq_affinity.sort_unstable_by_key(|(irq, ..)| *irq);

        Ok(Self {
            default_affinity,
            irq_affinity,
        })
    }

    fn apply(&self, is_enter: bool, args: &SysConfArgs) -> Result<()> {
        if let Some((prev, new)) = &self.default_affinity {
            let value = if is_enter { new } else { prev };
            write_vfile(Self::DEFAULT_AFFINITY_PATH, value)?;
        }

        let mut ignored_errors = Vec::new();
        let mut errors = Vec::new();
        for (irq, prev_masks, new_masks) in &self.irq_affinity {
            let value = if is_enter { new_masks } else { prev_masks };
            if let Err(err) = write_vfile(&Self::irq_smp_affinity_path(*irq), value) {
                // Ignore EIO for unmaskable IRQs.
                if err
                    .downcast_ref::<std::io::Error>()
                    .and_then(|err| err.raw_os_error())
                    == Some(nix::errno::Errno::EIO as i32)
                {
                    ignored_errors.push(*irq);
                } else {
                    errors.push((*irq, err));
                }
            }
        }

        for (irq, err) in errors {
            args.verbosity.warning(format_args!(
                "failed to set smp_affinity of IRQ {irq}: {err}"
            ));
        }
        if !ignored_errors.is_empty() {
            args.verbosity.note(format_args!(
                "skipped smp_affinity of unmovable IRQs: {}",
                ignored_errors.iter().join(", "),
            ));
        }

        Ok(())
    }
}
