use std::net::Ipv4Addr;

use winapi::{
    shared::{
        ipmib::{MIB_IPFORWARDROW, MIB_IPROUTE_TYPE_DIRECT},
        nldef::MIB_IPPROTO_NETMGMT,
        winerror::{
            ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
            ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR,
        },
    },
    um::iphlpapi,
};

use crate::types::{Result, TrojanError};

pub fn route_add_with_if(dst: u32, mask: u32, gw: u32, if_index: u32) -> Result<()> {
    log::trace!(
        "route add {} mask {} {} metric 1 if {}",
        Ipv4Addr::from(dst),
        Ipv4Addr::from(mask),
        Ipv4Addr::from(gw),
        if_index
    );
    let mut forward = MIB_IPFORWARDROW {
        dwForwardDest: dst.to_be(),
        dwForwardMask: mask.to_be(),
        dwForwardPolicy: 0,
        dwForwardNextHop: gw.to_be(),
        dwForwardIfIndex: if_index,
        ForwardType: MIB_IPROUTE_TYPE_DIRECT,
        ForwardProto: MIB_IPPROTO_NETMGMT,
        dwForwardAge: 0,
        dwForwardNextHopAS: 0,
        dwForwardMetric1: 99,
        dwForwardMetric2: !0,
        dwForwardMetric3: !0,
        dwForwardMetric4: !0,
        dwForwardMetric5: !0,
    };

    let ret = unsafe { iphlpapi::CreateIpForwardEntry(&mut forward) };
    match ret {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        ERROR_INVALID_PARAMETER => Err(TrojanError::Winapi("route add invalid parameter".into())),
        ERROR_NOT_SUPPORTED => Err(TrojanError::Winapi("route add not supported".into())),
        ERROR_ACCESS_DENIED => Err(TrojanError::Winapi("route add access denied".into())),
        _ => Err(TrojanError::Winapi("route add error unknown".into())),
    }
}
