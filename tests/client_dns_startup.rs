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
    assert!(
        source.contains("wintun was stopped while waiting for adapter readiness"),
        "dns startup should abort when wintun is stopped during adapter readiness wait"
    );
    assert!(
        source.contains("wintun was stopped before dns sidecar was registered"),
        "dns startup should kill the dns sidecar if wintun is stopped before registration"
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

#[test]
fn trojan_client_reports_starting_until_dns_is_ready() {
    let backend = include_str!("../trojan-client/src-tauri/src/main.rs");
    let frontend = include_str!("../trojan-client/src/app.vue");

    assert!(
        backend.contains("emit_state_update_event(ClientState::Starting"),
        "backend should report starting immediately after start is accepted"
    );
    assert!(
        backend.contains("emit_state_update_event(ClientState::Running"),
        "backend should report running only after sidecars are ready"
    );

    let dns_registered = backend
        .find("state.dns.replace(child)")
        .expect("dns child should be stored after it starts");
    let running_emitted = backend[dns_registered..]
        .find("emit_state_update_event(ClientState::Running")
        .map(|offset| dns_registered + offset)
        .expect("running state should be emitted after startup completes");
    assert!(
        dns_registered < running_emitted,
        "running state should be emitted after the dns sidecar is registered"
    );

    assert!(
        frontend.contains("connectionState: \"stopped\""),
        "frontend should track stopped/starting/running state explicitly"
    );
    assert!(
        frontend.contains("this.connectionState = \"starting\""),
        "start click should immediately move the button into starting state"
    );
    assert!(
        frontend.contains("this.label = \"启动中\""),
        "button label should show starting while startup is in progress"
    );
}

#[test]
fn trojan_client_disables_stop_while_starting() {
    let backend = include_str!("../trojan-client/src-tauri/src/main.rs");
    let frontend = include_str!("../trojan-client/src/app.vue");

    assert!(
        backend.contains("state.status == ClientState::Starting"),
        "backend stop command should ignore requests while startup is in progress"
    );
    assert!(
        frontend.contains("this.connectionState === \"starting\""),
        "frontend should treat starting as a disabled action state"
    );
    assert!(
        frontend.contains(":disabled=\"is_action_disabled()\""),
        "start/stop button should be disabled while startup is in progress"
    );
}
