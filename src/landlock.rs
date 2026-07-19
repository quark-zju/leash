use anyhow::{Context, Result};
use landlock::{
    AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};

const ALLOWED_TCP_CONNECT_PORTS: [u16; 2] = [53, 443];

pub(crate) fn restrict_network() -> Result<()> {
    let ruleset = tcp_connect_ruleset(Ruleset::default())
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

fn tcp_connect_ruleset(ruleset: Ruleset) -> Result<RulesetCreated> {
    let mut ruleset = ruleset
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessNet::ConnectTcp)?
        .create()
        .context("failed to create Landlock network ruleset")?;

    for port in ALLOWED_TCP_CONNECT_PORTS {
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
        let ruleset =
            tcp_connect_ruleset(Ruleset::default()).expect("create ruleset should always succeed");
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
    fn policy_allows_dns_and_https_ports() {
        assert_eq!(ALLOWED_TCP_CONNECT_PORTS, [53, 443]);
    }
}
