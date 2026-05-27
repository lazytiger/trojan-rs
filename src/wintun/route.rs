use std::{net::Ipv4Addr, ptr, slice};

use winapi::{
    shared::{
        ipmib::{MIB_IPFORWARDROW, MIB_IPFORWARDTABLE, MIB_IPROUTE_TYPE_DIRECT},
        nldef::MIB_IPPROTO_NETMGMT,
        winerror::{
            ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
            ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_NO_DATA, ERROR_OBJECT_ALREADY_EXISTS,
            NO_ERROR,
        },
    },
    um::iphlpapi,
};

use crate::types::{Result, TrojanError};

const ROUTE_METRIC: u32 = 99;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSpec {
    dst: u32,
    mask: u32,
    gw: u32,
    if_index: u32,
}

impl RouteSpec {
    pub fn new(dst: u32, mask: u32, gw: u32, if_index: u32) -> Self {
        Self {
            dst,
            mask,
            gw,
            if_index,
        }
    }
}

#[derive(Debug, Default)]
pub struct RouteApplyStats {
    pub total: usize,
    pub skipped: usize,
    pub added: usize,
    pub refreshed: usize,
}

struct RoutePlan {
    skipped: usize,
    added: usize,
    refreshed: usize,
    to_delete: Vec<MIB_IPFORWARDROW>,
    to_add: Vec<RouteSpec>,
}

fn route_row(spec: RouteSpec) -> MIB_IPFORWARDROW {
    MIB_IPFORWARDROW {
        dwForwardDest: spec.dst.to_be(),
        dwForwardMask: spec.mask.to_be(),
        dwForwardPolicy: 0,
        dwForwardNextHop: spec.gw.to_be(),
        dwForwardIfIndex: spec.if_index,
        ForwardType: MIB_IPROUTE_TYPE_DIRECT,
        ForwardProto: MIB_IPPROTO_NETMGMT,
        dwForwardAge: 0,
        dwForwardNextHopAS: 0,
        dwForwardMetric1: ROUTE_METRIC,
        dwForwardMetric2: !0,
        dwForwardMetric3: !0,
        dwForwardMetric4: !0,
        dwForwardMetric5: !0,
    }
}

fn is_managed_route(row: &MIB_IPFORWARDROW, spec: RouteSpec) -> bool {
    row.dwForwardDest == spec.dst.to_be()
        && row.dwForwardMask == spec.mask.to_be()
        && row.ForwardProto == MIB_IPPROTO_NETMGMT
        && row.dwForwardMetric1 == ROUTE_METRIC
}

fn route_matches(row: &MIB_IPFORWARDROW, spec: RouteSpec) -> bool {
    is_managed_route(row, spec)
        && row.dwForwardNextHop == spec.gw.to_be()
        && row.dwForwardIfIndex == spec.if_index
}

fn plan_route_updates(desired: &[RouteSpec], existing: &[MIB_IPFORWARDROW]) -> RoutePlan {
    let mut plan = RoutePlan {
        skipped: 0,
        added: 0,
        refreshed: 0,
        to_delete: Vec::new(),
        to_add: Vec::new(),
    };

    for &spec in desired {
        let managed: Vec<_> = existing
            .iter()
            .copied()
            .filter(|row| is_managed_route(row, spec))
            .collect();
        let has_exact = managed.iter().any(|row| route_matches(row, spec));
        let stale: Vec<_> = managed
            .into_iter()
            .filter(|row| !route_matches(row, spec))
            .collect();
        let has_stale = !stale.is_empty();

        plan.to_delete.extend(stale);

        if has_exact {
            plan.skipped += 1;
        } else {
            if has_stale {
                plan.refreshed += 1;
            } else {
                plan.added += 1;
            }
            plan.to_add.push(spec);
        }
    }

    plan
}

fn route_error(action: &str, ret: u32) -> TrojanError {
    match ret {
        ERROR_INVALID_PARAMETER => {
            TrojanError::Winapi(format!("route {} invalid parameter", action))
        }
        ERROR_NOT_SUPPORTED => TrojanError::Winapi(format!("route {} not supported", action)),
        ERROR_ACCESS_DENIED => TrojanError::Winapi(format!("route {} access denied", action)),
        _ => TrojanError::Winapi(format!("route {} error unknown:{}", action, ret)),
    }
}

fn route_rows() -> Result<Vec<MIB_IPFORWARDROW>> {
    let mut size = 0u32;
    let ret = unsafe { iphlpapi::GetIpForwardTable(ptr::null_mut(), &mut size, 0) };
    match ret {
        ERROR_INSUFFICIENT_BUFFER => {}
        ERROR_NO_DATA => return Ok(Vec::new()),
        _ => return Err(route_error("list", ret)),
    }

    let mut buffer = vec![0u8; size as usize];
    let table = buffer.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;
    let ret = unsafe { iphlpapi::GetIpForwardTable(table, &mut size, 0) };
    match ret {
        NO_ERROR => {
            let table = unsafe { &*table };
            let rows =
                unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
            Ok(rows.to_vec())
        }
        ERROR_NO_DATA => Ok(Vec::new()),
        _ => Err(route_error("list", ret)),
    }
}

fn delete_routes(routes: Vec<MIB_IPFORWARDROW>) -> Result<()> {
    for mut route in routes {
        log::warn!(
            "route exists, delete stale {} mask {} {} metric {} if {}",
            Ipv4Addr::from(u32::from_be(route.dwForwardDest)),
            Ipv4Addr::from(u32::from_be(route.dwForwardMask)),
            Ipv4Addr::from(u32::from_be(route.dwForwardNextHop)),
            route.dwForwardMetric1,
            route.dwForwardIfIndex
        );
        let ret = unsafe { iphlpapi::DeleteIpForwardEntry(&mut route) };
        if ret != NO_ERROR && ret != ERROR_NOT_FOUND {
            return Err(route_error("delete", ret));
        }
    }
    Ok(())
}

fn add_route(spec: RouteSpec) -> Result<()> {
    let mut forward = route_row(spec);
    let ret = unsafe { iphlpapi::CreateIpForwardEntry(&mut forward) };
    match ret {
        NO_ERROR => Ok(()),
        ERROR_OBJECT_ALREADY_EXISTS => Err(TrojanError::Winapi(format!(
            "route add already exists: {} mask {} {} if {}",
            Ipv4Addr::from(spec.dst),
            Ipv4Addr::from(spec.mask),
            Ipv4Addr::from(spec.gw),
            spec.if_index
        ))),
        _ => Err(route_error("add", ret)),
    }
}

pub fn route_add_many_with_if(routes: &[RouteSpec]) -> Result<RouteApplyStats> {
    let existing = route_rows()?;
    let plan = plan_route_updates(routes, &existing);
    delete_routes(plan.to_delete)?;
    for &spec in &plan.to_add {
        log::trace!(
            "route add {} mask {} {} metric {} if {}",
            Ipv4Addr::from(spec.dst),
            Ipv4Addr::from(spec.mask),
            Ipv4Addr::from(spec.gw),
            ROUTE_METRIC,
            spec.if_index
        );
        add_route(spec)?;
    }

    Ok(RouteApplyStats {
        total: routes.len(),
        skipped: plan.skipped,
        added: plan.added,
        refreshed: plan.refreshed,
    })
}

pub fn route_add_with_if(dst: u32, mask: u32, gw: u32, if_index: u32) -> Result<()> {
    route_add_many_with_if(&[RouteSpec::new(dst, mask, gw, if_index)]).map(|_| ())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn row(dst: u32, mask: u32, gw: u32, if_index: u32) -> MIB_IPFORWARDROW {
        MIB_IPFORWARDROW {
            dwForwardDest: dst.to_be(),
            dwForwardMask: mask.to_be(),
            dwForwardPolicy: 0,
            dwForwardNextHop: gw.to_be(),
            dwForwardIfIndex: if_index,
            ForwardType: MIB_IPROUTE_TYPE_DIRECT,
            ForwardProto: MIB_IPPROTO_NETMGMT,
            dwForwardAge: 0,
            dwForwardNextHopAS: 0,
            dwForwardMetric1: ROUTE_METRIC,
            dwForwardMetric2: !0,
            dwForwardMetric3: !0,
            dwForwardMetric4: !0,
            dwForwardMetric5: !0,
        }
    }

    #[test]
    fn plan_skips_routes_that_already_match() {
        let desired = vec![RouteSpec::new(0x01020300, 0xffffff00, 0xc0a80101, 12)];
        let existing = vec![row(0x01020300, 0xffffff00, 0xc0a80101, 12)];

        let plan = plan_route_updates(&desired, &existing);

        assert_eq!(plan.skipped, 1);
        assert!(plan.to_delete.is_empty());
        assert!(plan.to_add.is_empty());
    }

    #[test]
    fn plan_refreshes_managed_routes_with_stale_gateway_or_interface() {
        let desired = vec![RouteSpec::new(0x01020300, 0xffffff00, 0xc0a80101, 12)];
        let existing = vec![row(0x01020300, 0xffffff00, 0xc0a80201, 13)];

        let plan = plan_route_updates(&desired, &existing);

        assert_eq!(plan.skipped, 0);
        assert_eq!(plan.to_delete.len(), 1);
        assert_eq!(plan.to_add, desired);
    }
}
