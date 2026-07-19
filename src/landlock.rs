use anyhow::{Context, Result};
use landlock::{
    AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr,
};

const ALLOWED_TCP_CONNECT_PORTS: [u16; 2] = [53, 443];

pub(crate) fn restrict_network() -> Result<()> {
    tcp_connect_ruleset(Ruleset::default())?
        .restrict_self()
        .context("failed to enforce Landlock network rules")?;
    Ok(())
}

fn tcp_connect_ruleset(ruleset: Ruleset) -> Result<RulesetCreated> {
    let mut ruleset = ruleset
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessNet::ConnectTcp)
        .context("TCP connect restrictions require Landlock ABI 4 or newer")?
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
        let result = tcp_connect_ruleset(Ruleset::default());
        if abi >= 4 {
            result.expect("ABI 4 or newer supports TCP connect rules");
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn policy_allows_dns_and_https_ports() {
        assert_eq!(ALLOWED_TCP_CONNECT_PORTS, [53, 443]);
    }
}
