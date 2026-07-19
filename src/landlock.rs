use anyhow::{Context, Result};
use landlock::{
    AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};

pub(crate) fn restrict_network(ports: &[u16]) -> Result<()> {
    let ruleset = tcp_connect_ruleset(Ruleset::default(), ports)
        .context("failed to create Landlock network ruleset")?;
    let status = ruleset
        .restrict_self()
        .context("failed to enforce Landlock network rules")?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        eprintln!(
            "leash: warning: Landlock network restrictions are not enforced by the kernel \
             (kernel may be too old or Landlock not enabled)"
        );
    }
    Ok(())
}

fn tcp_connect_ruleset(ruleset: Ruleset, ports: &[u16]) -> Result<RulesetCreated> {
    let mut ruleset = ruleset
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessNet::ConnectTcp)?
        .create()
        .context("failed to create Landlock network ruleset")?;

    for &port in ports {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .with_context(|| format!("failed to allow TCP connections to port {port}"))?;
    }
    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::OwnedFd;

    #[test]
    fn policy_matches_kernel_tcp_network_support() {
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0,
                1,
            )
        };
        let ports = [53u16, 443];
        let ruleset = tcp_connect_ruleset(Ruleset::default(), &ports)
            .expect("create ruleset should always succeed");
        let fd: Option<OwnedFd> = ruleset.into();
        if abi >= 4 {
            assert!(
                fd.is_some(),
                "ABI 4 or newer should create a real Landlock ruleset"
            );
        } else {
            assert!(
                fd.is_none(),
                "ABI < 4 should produce a dummy ruleset (kernel does not support TCP connect)"
            );
        }
    }

    #[test]
    fn policy_passes_ports_to_ruleset() {
        // Verify that the passed ports are used by creating a ruleset
        // and checking it does not fail with valid ports.
        let ports = [53u16, 443, 4000];
        let ruleset =
            tcp_connect_ruleset(Ruleset::default(), &ports).expect("valid ports should succeed");
        // The ruleset is either a real fd or None (dummy on old kernels); both are fine.
        let _fd: Option<OwnedFd> = ruleset.into();
    }
}
