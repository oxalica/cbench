use std::fs;

use anyhow::{ensure, Context, Result};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use crate::SERVICE_NAME;

/// Extensible system configuration change unit.
#[typetag::serde(tag = "type")]
pub trait SysConf: std::fmt::Debug {
    fn enter(&self) -> Result<()>;
    fn leave(&self) -> Result<()>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Aslr {
    prev: Option<String>,
}

impl Aslr {
    const CTL_PATH: &'static str = "/proc/sys/kernel/randomize_va_space";

    pub fn init() -> Result<Self> {
        let st = fs::read_to_string(Self::CTL_PATH).context("failed to get current ASLR state")?;
        let st = if st.trim() == "0" {
            eprintln!("{}: ASLR is already disabled", "warning".yellow().bold());
            None
        } else {
            Some(st)
        };
        Ok(Self { prev: st })
    }
}

#[typetag::serde]
impl SysConf for Aslr {
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
pub struct CpusetExclusive;

#[typetag::serde]
impl SysConf for CpusetExclusive {
    fn enter(&self) -> Result<()> {
        fs::write(
            format!("/sys/fs/cgroup/{SERVICE_NAME}/cpuset.cpus.partition"),
            "root",
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
pub struct DisableSiblingCpus(Vec<u32>);

impl DisableSiblingCpus {
    /// # Panics
    ///
    /// Panic if `cpus` is not sorted or have duplicated elements.
    pub fn init(cpus: &[u32]) -> Result<Self> {
        assert!(
            cpus.windows(2).all(|w| w[0] < w[1]),
            "CPUs should be sorted and deduplicated",
        );

        let mut sibling_cpus = Vec::new();
        for &cpu in cpus {
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
                        !cpus.contains(&sibling),
                        "CPU {cpu} and {sibling} are siblings, only one can be specified",
                    );
                    sibling_cpus.push(sibling);
                }
            }
        }
        sibling_cpus.sort_unstable();
        sibling_cpus.dedup();
        ensure!(
            !cpus.contains(&0) && !sibling_cpus.contains(&0),
            "CPU 0 and its siblints are not allowed for exclusive use",
        );
        ensure!(cpus != sibling_cpus, "all allowed CPUs are siblings");
        Ok(Self(sibling_cpus))
    }

    fn setup(&self, op: &str, value: &str) -> Result<()> {
        for &cpu in &self.0 {
            let ctl_path = format!("/sys/devices/system/cpu/cpu{cpu}/online");
            fs::write(ctl_path, value).with_context(|| format!("failed to {op} CPU {cpu}"))?;
        }
        Ok(())
    }
}

#[typetag::serde]
impl SysConf for DisableSiblingCpus {
    fn enter(&self) -> Result<()> {
        self.setup("disable", "0")
    }

    fn leave(&self) -> Result<()> {
        self.setup("enable", "1")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpuFreq {
    governors: Vec<(u32, String)>,
}

impl CpuFreq {
    /// # Panics
    ///
    /// Panic if `cpus` is not sorted or have duplicated elements.
    pub fn init(cpus: &[u32]) -> Result<Self> {
        assert!(
            cpus.windows(2).all(|w| w[0] < w[1]),
            "CPUs should be sorted and deduplicated",
        );
        let governors = cpus
            .iter()
            .map(|&cpu| {
                let gov = fs::read_to_string(Self::governor_ctl_path(cpu))
                    .with_context(|| format!("failed to read scaling governor of CPU {cpu}"))?;
                Ok((cpu, gov))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { governors })
    }

    fn governor_ctl_path(cpu: u32) -> String {
        format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
    }

    fn set_governors(&self, new_gov: Option<&str>) -> Result<()> {
        for (cpu, prev_gov) in &self.governors {
            let gov = new_gov.unwrap_or(prev_gov);
            fs::write(Self::governor_ctl_path(*cpu), gov)
                .with_context(|| format!("failed to set scaling governor of CPU {cpu} to {gov}"))?;
        }
        Ok(())
    }
}

#[typetag::serde]
impl SysConf for CpuFreq {
    fn enter(&self) -> Result<()> {
        self.set_governors(Some("performance"))
    }

    fn leave(&self) -> Result<()> {
        self.set_governors(None)
    }
}
