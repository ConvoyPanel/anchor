use std::{collections::BTreeSet, path::Path};

use serde::Serialize;

use crate::{
    api::{AGENT_CAPABILITIES, RELAY_CAPABILITIES, TEMPLATE_CAPABILITY},
    config::Mode,
    protocol::{PROTOCOL_MAX, PROTOCOL_MIN},
};

/// What this machine says about itself when it asks to join a panel.
///
/// Every field is optional and every probe is best-effort. A host that cannot
/// answer one of these questions is still a host worth enrolling, and failing
/// the install over a fact nobody schedules against would trade a working node
/// for a tidier payload.
///
/// Nothing here is authority. The panel treats it as evidence for a human
/// making a decision, and takes the one reachability claim that matters -- the
/// address the request actually came from -- from the connection instead.
///
/// Two facts the plan lists are deliberately absent, because the panel can
/// source them better itself once credentials exist: the PVE version and the
/// cluster CA fingerprint both come back from the Proxmox API, over an
/// authenticated channel, through code the panel already has and tests
/// (`ClusterIdentityService`). Parsing them out of `/etc/pve` here would be a
/// second implementation of an answer we can simply ask for.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pve_node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Cpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    pub version: &'static str,
    pub protocol: ProtocolRange,
    pub capabilities: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Cpu {
    pub sockets: u32,
    pub cores: u32,
    pub threads: u32,
}

#[derive(Debug, Serialize)]
pub struct ProtocolRange {
    pub min: u16,
    pub max: u16,
}

impl Default for ProtocolRange {
    fn default() -> Self {
        Self {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        }
    }
}

impl Report {
    /// Gathers what this host will admit to, reading the filesystem directly.
    ///
    /// `/proc` and `/etc/pve` rather than `pvesh`: enrollment runs before there
    /// is any configuration, so there is no `qm_path` to trust yet, and a probe
    /// that cannot spawn anything cannot hang on a subprocess that never exits.
    pub async fn gather(mode: Mode) -> Self {
        let hostname = read_trimmed("/proc/sys/kernel/hostname").await;

        Self {
            pve_node_name: pve_node_name(Path::new("/etc/pve/local"))
                .await
                // PVE names a node after its short hostname, so this is the
                // same answer by a less direct route -- worth having, because
                // /etc/pve is a fuse mount that is not there before the cluster
                // service starts.
                .or_else(|| hostname.as_deref().and_then(short_hostname)),
            hostname,
            cluster_name: read_trimmed("/etc/pve/corosync.conf")
                .await
                .as_deref()
                .and_then(cluster_name),
            cpu: read_trimmed("/proc/cpuinfo").await.as_deref().and_then(cpu),
            memory_bytes: read_trimmed("/proc/meminfo")
                .await
                .as_deref()
                .and_then(memory_bytes),
            version: env!("CARGO_PKG_VERSION"),
            protocol: ProtocolRange::default(),
            capabilities: capabilities(mode),
        }
    }
}

fn capabilities(mode: Mode) -> Vec<&'static str> {
    match mode {
        Mode::Relay => RELAY_CAPABILITIES.to_vec(),
        Mode::Agent => {
            // Templates default to enabled and there is no configuration yet to
            // say otherwise. The heartbeat reports the settled answer a minute
            // later; this is only ever the opening claim.
            let mut capabilities = AGENT_CAPABILITIES.to_vec();
            capabilities.push(TEMPLATE_CAPABILITY);
            capabilities
        }
    }
}

async fn read_trimmed(path: &str) -> Option<String> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|contents| contents.trim().to_owned())
}

/// The node name PVE uses, read from the `/etc/pve/local` symlink.
///
/// It points at `nodes/<name>`, and that name is what every `qm` path and
/// cluster message is keyed by -- so it is what the panel's `nodes.name` has to
/// match exactly.
async fn pve_node_name(local: &Path) -> Option<String> {
    let target = tokio::fs::read_link(local).await.ok()?;

    target
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn short_hostname(hostname: &str) -> Option<String> {
    hostname
        .split('.')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// Pulled from `corosync.conf` rather than guessed: a node with no such file is
/// standalone, which is a real answer and not a missing one.
fn cluster_name(corosync: &str) -> Option<String> {
    corosync.lines().find_map(|line| {
        line.trim()
            .strip_prefix("cluster_name:")
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
    })
}

/// Sockets, physical cores and threads from `/proc/cpuinfo`.
///
/// `physical id` is absent on single-socket machines and on most guests, where
/// one socket is the right answer rather than none. `cpu cores` is per socket,
/// so the total is the product -- reporting the per-socket figure as the whole
/// machine is how a 2×32 host gets scheduled as if it had 32 cores.
fn cpu(cpuinfo: &str) -> Option<Cpu> {
    let mut sockets = BTreeSet::new();
    let mut threads = 0u32;
    let mut cores_per_socket = None;

    for line in cpuinfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());

        match key {
            "processor" => threads += 1,
            "physical id" => {
                sockets.insert(value.to_owned());
            }
            "cpu cores" => cores_per_socket = value.parse::<u32>().ok().or(cores_per_socket),
            _ => {}
        }
    }

    if threads == 0 {
        return None;
    }

    let sockets = sockets.len().max(1) as u32;

    Some(Cpu {
        sockets,
        // Without `cpu cores` the kernel is not exposing SMT topology, and the
        // honest reading is one core per thread rather than a guessed ratio.
        cores: cores_per_socket.map_or(threads, |cores| cores * sockets),
        threads,
    })
}

/// `MemTotal` is in kibibytes; the panel stores bytes.
fn memory_bytes(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|line| line.trim().strip_prefix("MemTotal:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|kib| kib.parse::<u64>().ok())
        .map(|kib| kib * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_SOCKET: &str = "\
processor\t: 0
physical id\t: 0
cpu cores\t: 32
processor\t: 1
physical id\t: 1
cpu cores\t: 32
";

    #[test]
    fn multiplies_cores_by_sockets() {
        let cpu = cpu(TWO_SOCKET).unwrap();

        // The failure this guards: reporting 32 for a machine with 64 physical
        // cores, which under-schedules the host by half.
        assert_eq!(cpu.sockets, 2);
        assert_eq!(cpu.cores, 64);
        assert_eq!(cpu.threads, 2);
    }

    #[test]
    fn treats_a_guest_without_topology_as_one_socket() {
        let cpu = cpu("processor\t: 0\nprocessor\t: 1\n").unwrap();

        assert_eq!(cpu.sockets, 1);
        // No `cpu cores` line means no SMT information, so a thread is a core.
        assert_eq!(cpu.cores, 2);
        assert_eq!(cpu.threads, 2);
    }

    #[test]
    fn reports_nothing_rather_than_zero_for_unreadable_cpuinfo() {
        assert!(cpu("").is_none());
    }

    #[test]
    fn converts_memtotal_from_kibibytes() {
        let meminfo = "MemTotal:       16373888 kB\nMemFree:         123 kB\n";

        assert_eq!(memory_bytes(meminfo), Some(16_766_861_312));
        assert!(memory_bytes("MemFree: 1 kB").is_none());
    }

    #[test]
    fn finds_the_cluster_name_and_admits_when_there_is_none() {
        let corosync = "totem {\n  cluster_name: prod\n  version: 2\n}\n";

        assert_eq!(cluster_name(corosync).as_deref(), Some("prod"));
        assert!(cluster_name("totem {\n  version: 2\n}").is_none());
    }

    #[test]
    fn falls_back_from_fqdn_to_short_hostname() {
        assert_eq!(
            short_hostname("pve-07.example.com").as_deref(),
            Some("pve-07")
        );
        assert_eq!(short_hostname("pve-07").as_deref(), Some("pve-07"));
        assert!(short_hostname("").is_none());
    }

    #[tokio::test]
    async fn reads_the_node_name_from_the_pve_local_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let nodes = dir.path().join("nodes/pve-07");
        std::fs::create_dir_all(&nodes).unwrap();
        let local = dir.path().join("local");
        std::os::unix::fs::symlink(&nodes, &local).unwrap();

        assert_eq!(pve_node_name(&local).await.as_deref(), Some("pve-07"));
        assert!(pve_node_name(&dir.path().join("missing")).await.is_none());
    }
}
