use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;

use anyhow::{bail, ensure, Context, Result};
use itertools::Itertools;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use crate::SERVICE_NAME;

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

#[derive(Debug)]
pub struct SysConfArgs {
    pub cpus: BTreeSet<u32>,
    pub isolated: bool,
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

    fn enter(&self) -> Result<()>;

    fn leave(&self) -> Result<()>;
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
    fn init(_: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let st = fs::read_to_string(Self::CTL_PATH).context("failed to get current ASLR state")?;
        let st = if st.trim() == "0" {
            eprintln!("{}: ASLR is already disabled", "warning".yellow().bold());
            None
        } else {
            Some(st)
        };
        Ok(Self { prev: st })
    }

    fn enter(&self) -> Result<()> {
        fs::write(Self::CTL_PATH, "0").context("failed to disable ASLR")
    }

    fn leave(&self) -> Result<()> {
        if let Some(prev) = &self.prev {
            fs::write(Self::CTL_PATH, prev)
                .with_context(|| format!("failed to reset ASLR to {prev}"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpusetExclusive {
    isolated: bool,
}

impl CpusetExclusive {
    const NAME: &'static str = "cpuset";
    const HELP: &'static str = "Pin the process' cgroup on specific CPU(s) for exclusive use";
}

#[typetag::serde]
impl SysConf for CpusetExclusive {
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            isolated: args.isolated,
        })
    }

    fn enter(&self) -> Result<()> {
        let value = if self.isolated { "isolated" } else { "root" };
        fs::write(
            format!("/sys/fs/cgroup/{SERVICE_NAME}/cpuset.cpus.partition"),
            value,
        )
        .context("failed to set cpuset partition to root")
    }

    fn leave(&self) -> Result<()> {
        // The whole cgroup will be removed by systemd after the service exit.
        // Nothing need to be done here.
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoHyperThreading(Vec<u32>);

impl NoHyperThreading {
    const NAME: &'static str = "noht";
    const HELP: &'static str = "Disable (set offline) CPU thread siblings of the CPU(s) used if hyper-threading is enabled";

    fn setup(&self, op: &str, value: &str) -> Result<()> {
        for &cpu in &self.0 {
            let ctl_path = format!("/sys/devices/system/cpu/cpu{cpu}/online");
            fs::write(ctl_path, value).with_context(|| format!("failed to {op} CPU {cpu}"))?;
        }
        Ok(())
    }
}

#[typetag::serde]
impl SysConf for NoHyperThreading {
    /// # Panics
    ///
    /// Panic if `cpus` is not sorted or have duplicated elements.
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let mut sibling_cpus = Vec::new();
        for &cpu in &args.cpus {
            let sibling_path =
                format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
            let siblings = fs::read_to_string(sibling_path).with_context(|| {
                format!("failed to get siblings of CPU {cpu}, index out of bound?")
            })?;
            for sibling in siblings.trim_end().split(',') {
                let sibling = sibling.parse::<u32>().with_context(|| {
                    format!("failed to parse siblings of CPU {cpu}: {siblings:?}")
                })?;
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
        Ok(Self(sibling_cpus))
    }

    fn enter(&self) -> Result<()> {
        self.setup("disable", "0")
    }

    fn leave(&self) -> Result<()> {
        self.setup("enable", "1")
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

    fn get_boost() -> Result<CpuBoost> {
        match fs::read_to_string(Self::INTEL_NO_TURBO_PATH) {
            Ok(s) if s.trim() != "1" => return Ok(CpuBoost::IntelNoTurbo(s)),
            Ok(_) => {
                eprintln!(
                    "{}: Intel CPU turbo is already disabled",
                    "warning".yellow().bold()
                );
                return Ok(CpuBoost::Ignore);
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => bail!(err),
        }

        match fs::read_to_string(Self::CPUFREQ_BOOST_PATH) {
            Ok(s) if s.trim() != "0" => return Ok(CpuBoost::CpufreqBoost(s)),
            Ok(_) => {
                eprintln!(
                    "{}: cpufreq boost is already disabled",
                    "warning".yellow().bold()
                );
                return Ok(CpuBoost::Ignore);
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => bail!(err),
        }

        if fs::read_to_string(Self::AMD_PSTATE_STATUS_PATH).is_ok_and(|s| s.trim() == "active") {
            // amd_pstate=active detected.
            let mut prev_prefs = fs::read_dir("/sys/devices/system/cpu")?
                .map(|ent| {
                    let ent = ent?;
                    let path = ent.path();
                    if !ent.file_type()?.is_dir() {
                        return Ok(None);
                    }
                    let Some(cpu) = path
                        .file_name()
                        .and_then(|s| s.to_str()?.strip_prefix("cpu")?.parse::<u32>().ok())
                    else {
                        return Ok(None);
                    };
                    let pref_path = path.join("cpufreq/energy_performance_preference");
                    match fs::read_to_string(&pref_path)
                        .with_context(|| format!("failed to read {}", pref_path.display()))
                    {
                        Ok(pref) => Ok(Some((cpu, pref))),
                        // The file does not exist when CPU's offline. Skip in that case.
                        Err(err)
                            if err.downcast_ref::<std::io::Error>().unwrap().kind()
                                == ErrorKind::NotFound
                                && fs::read_to_string(path.join("online"))
                                    .is_ok_and(|s| s.trim() == "0") =>
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

        eprintln!(
            "{}: unsupported CPU and/or cpufreq driver, skip disabling turbo/boost",
            "warning".yellow().bold()
        );
        Ok(CpuBoost::Ignore)
    }

    fn governor_ctl_path(cpu: u32) -> String {
        format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
    }

    fn set_governors(&self, new_gov: Option<&str>) -> Result<()> {
        for (cpu, prev_gov) in &self.prev_governors {
            let gov = new_gov.unwrap_or(prev_gov);
            fs::write(Self::governor_ctl_path(*cpu), gov)
                .with_context(|| format!("failed to set scaling governor of CPU {cpu} to {gov}"))?;
        }
        Ok(())
    }
}

#[typetag::serde]
impl SysConf for CpuFreq {
    /// # Panics
    ///
    /// Panic if `cpus` is not sorted or have duplicated elements.
    fn init(args: &SysConfArgs) -> Result<Self>
    where
        Self: Sized,
    {
        let prev_governors = args
            .cpus
            .iter()
            .map(|&cpu| {
                let gov = fs::read_to_string(Self::governor_ctl_path(cpu))
                    .with_context(|| format!("failed to read scaling governor of CPU {cpu}"))?;
                Ok((cpu, gov))
            })
            .collect::<Result<Vec<_>>>()?;
        let prev_turbo = Self::get_boost()?;
        Ok(Self {
            prev_governors,
            prev_boost: prev_turbo,
        })
    }

    fn enter(&self) -> Result<()> {
        match &self.prev_boost {
            CpuBoost::Ignore => {}
            CpuBoost::IntelNoTurbo(_) => fs::write(Self::INTEL_NO_TURBO_PATH, "1")
                .context("failed to disable Intel CPU turbo")?,
            CpuBoost::CpufreqBoost(_) => {
                fs::write(Self::CPUFREQ_BOOST_PATH, "0")
                    .context("failed to disable cpufreq boost")?;
            }
            CpuBoost::AmdPstateActivePrefs(_) => {
                fs::write(Self::AMD_PSTATE_STATUS_PATH, "passive")
                    .context("failed to set amd_pstate to passive mode")?;
                fs::write(Self::CPUFREQ_BOOST_PATH, "0")
                    .context("failed to disable cpufreq boost")?;
            }
        }
        self.set_governors(Some("performance"))
    }

    fn leave(&self) -> Result<()> {
        // NB. This may change driver state of amd_pstate which resets governors.
        // Thus is need to be done before setting governors.
        match &self.prev_boost {
            CpuBoost::Ignore => {}
            CpuBoost::IntelNoTurbo(prev) => {
                fs::write(Self::INTEL_NO_TURBO_PATH, prev)
                    .with_context(|| format!("failed to reset Intel CPU turbo to {prev:?}"))?;
            }
            CpuBoost::CpufreqBoost(prev) => {
                fs::write(Self::CPUFREQ_BOOST_PATH, prev)
                    .with_context(|| format!("failed to reset cpufreq boost to {prev:?}"))?;
            }
            CpuBoost::AmdPstateActivePrefs(prefs) => {
                fs::write(Self::AMD_PSTATE_STATUS_PATH, "active")
                    .context("failed to set amd_pstate to active mode")?;
                for (cpu, pref) in prefs {
                    let ctl_path = format!(
                        "/sys/devices/system/cpu/cpu{cpu}/cpufreq/energy_performance_preference"
                    );
                    fs::write(ctl_path, pref).with_context(|| {
                        format!(
                            "failed to reset energy_performance_preference of CPU {cpu} to {pref:?}"
                        )
                    })?;
                }
            }
        }
        self.set_governors(None)
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
        let prev_masks =
            fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;

        let mut masks = prev_masks
            .trim()
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

    fn apply(&self, is_enter: bool) -> Result<()> {
        if let Some((prev, new)) = &self.default_affinity {
            let value = if is_enter { new } else { prev };
            fs::write(Self::DEFAULT_AFFINITY_PATH, value)
                .context("failed to set default_smp_affinity")?;
        }

        let mut errors = vec![];
        for (irq, prev_masks, new_masks) in &self.irq_affinity {
            let path = Self::irq_smp_affinity_path(*irq);
            let value = if is_enter { new_masks } else { prev_masks };
            if let Err(err) = fs::write(path, value) {
                // Ignore EIO for unmaskable IRQs.
                if !err
                    .raw_os_error()
                    .is_some_and(|err| err == nix::errno::Errno::EIO as i32)
                {
                    errors.push((*irq, err));
                }
            }
        }
        for (irq, err) in errors {
            eprintln!(
                "{}: failed to set smp_affinity of IRQ {irq}: {err}",
                "warning".yellow().bold(),
            );
        }
        Ok(())
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
        for ent in fs::read_dir("/proc/irq").context("failed to list /proc/irq")? {
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

    fn enter(&self) -> Result<()> {
        self.apply(true)
    }

    fn leave(&self) -> Result<()> {
        self.apply(false)
    }
}
