#[test]
fn trojan_client_dns_start_waits_for_tun_readiness() {
    let source = include_str!("../trojan-client/src-tauri/src/main.rs");
    let fixed_sleep = concat!("sleep", "(Duration::from_secs(10))");

    assert!(
        !source.contains(fixed_sleep),
        "dns startup should wait for explicit tun readiness instead of a fixed 10 second sleep"
    );
    assert!(
        source.contains("wait_tun_ready(&config.iface_name).await"),
        "dns startup should wait for the configured tun interface before spawning dns"
    );
}

#[test]
fn dns_sidecar_waits_for_strict_adapter_readiness() {
    let source = include_str!("../src/dns/mod.rs");

    assert!(
        source.contains("wait_tun_ready(OPTIONS.dns_args().tun_name.as_str())"),
        "dns sidecar should wait for the target tun adapter before binding sockets"
    );
    assert!(
        source.contains("get_adapter_ready"),
        "dns sidecar should use strict adapter readiness shared with the client"
    );
}
