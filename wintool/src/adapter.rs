#![allow(dead_code)]

use std::{
    ffi::CStr,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use widestring::{U16CStr, U16Str};
use winapi::{
    shared::{
        ifdef::IfOperStatusUp,
        ipifcons,
        minwindef::PULONG,
        ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
        winerror::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
        ws2def::{AF_UNSPEC, LPSOCKADDR},
    },
    um::{
        iphlpapi,
        iptypes::{GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES},
        winbase,
        winnt::MAKELANGID,
    },
};

pub struct AdapterAddresses<'a> {
    info: &'a IP_ADAPTER_ADDRESSES,
}

unsafe fn win_sockaddr_to_rust(address: LPSOCKADDR) -> Option<IpAddr> {
    address.as_ref().map(|addr| match addr.sa_family as i32 {
        winapi::shared::ws2def::AF_INET => {
            let addr = &*(address as *const _ as *const winapi::shared::ws2def::SOCKADDR_IN);
            IpAddr::V4(Ipv4Addr::from(addr.sin_addr.S_un.S_addr().to_ne_bytes()))
        }
        winapi::shared::ws2def::AF_INET6 => {
            let addr = &*(address as *const _ as *const winapi::shared::ws2ipdef::SOCKADDR_IN6);
            IpAddr::V6(Ipv6Addr::from(*addr.sin6_addr.u.Byte()))
        }
        _ => panic!("Unknown address family"),
    })
}

impl<'a> AdapterAddresses<'a> {
    pub fn new(info: &'a IP_ADAPTER_ADDRESSES) -> Self {
        Self { info }
    }

    pub fn if_index(&self) -> u32 {
        unsafe { self.info.u.s().IfIndex as u32 }
    }

    pub fn name(&self) -> String {
        unsafe {
            let str = CStr::from_ptr(self.info.AdapterName);
            str.to_string_lossy().to_string()
        }
    }

    pub fn description(&self) -> String {
        unsafe {
            let str = U16CStr::from_ptr_str(self.info.Description);
            str.to_string_lossy().to_string()
        }
    }

    pub fn gateway(&self) -> Vec<IpAddr> {
        unsafe {
            let mut gateway = Vec::new();
            let mut gateway_address = self.info.FirstGatewayAddress;
            while !gateway_address.is_null() {
                if let Some(addr) =
                    win_sockaddr_to_rust(gateway_address.as_ref().unwrap().Address.lpSockaddr)
                {
                    gateway.push(addr);
                }
                gateway_address = (*gateway_address).Next;
            }
            gateway
        }
    }

    pub fn dns(&self) -> Vec<IpAddr> {
        unsafe {
            let mut dns = Vec::new();
            let mut dns_server = self.info.FirstDnsServerAddress;
            while !dns_server.is_null() {
                if let Some(addr) =
                    win_sockaddr_to_rust(dns_server.as_ref().unwrap().Address.lpSockaddr)
                {
                    dns.push(addr);
                }
                dns_server = (*dns_server).Next;
            }
            dns
        }
    }
    pub fn address(&self) -> Vec<IpAddr> {
        unsafe {
            let mut address = Vec::new();
            let mut addr = self.info.FirstUnicastAddress;
            while !addr.is_null() {
                if let Some(addr) = win_sockaddr_to_rust(addr.as_ref().unwrap().Address.lpSockaddr)
                {
                    address.push(addr);
                }
                addr = (*addr).Next;
            }
            address
        }
    }

    pub fn is_up(&self) -> bool {
        self.info.OperStatus == IfOperStatusUp
    }

    pub fn is_ethernet(&self) -> bool {
        self.info.IfType == ipifcons::IF_TYPE_ETHERNET_CSMACD
            || self.info.IfType == ipifcons::IF_TYPE_IEEE80211
            || self.info.IfType == ipifcons::IF_TYPE_IEEE80212
    }

    pub fn is_dns_auto(&self) -> bool {
        let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let subkey = format!(
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
            self.name()
        );
        if let Ok(key) = hklm.open_subkey_with_flags(subkey.as_str(), winreg::enums::KEY_READ) {
            let value: String = key.get_value("NameServer").unwrap();
            value == ""
        } else {
            true
        }
    }

    pub fn set_dns_server(&self, name_server: String) -> bool {
        let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let subkey = format!(
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
            self.name()
        );
        if let Ok(key) = hklm.open_subkey_with_flags(
            subkey.as_str(),
            winreg::enums::KEY_READ | winreg::enums::KEY_WRITE,
        ) {
            if let Err(err) = key.set_value("NameServer", &name_server) {
                log::error!("set key:{} error:{}", subkey, err);
                false
            } else {
                true
            }
        } else {
            log::error!("registry key:{} not found", subkey);
            false
        }
    }

    pub fn is_main_adapter_v4(&self) -> bool {
        if !self.is_ethernet() || !self.is_up() {
            return false;
        }
        let ips = self.gateway();
        for ip in ips {
            if ip.is_ipv4() {
                let addr = self.address();
                for ip in addr {
                    if ip.is_ipv4() {
                        return true;
                    }
                }
            }
        }
        false
    }
}

pub fn get_adapter_ip(name: &str) -> Option<String> {
    let mut ret = None;
    unsafe {
        get_adapters_addresses(|adapter| {
            let adapter_name = adapter.description();
            if adapter_name.contains(name) {
                let ips = adapter.address();
                for ip in ips {
                    if ip.is_ipv4() {
                        ret = Some(ip.to_string());
                        return true;
                    }
                }
            }
            false
        });
    }
    ret
}

pub fn get_adapter_index(name: &str) -> Option<u32> {
    let mut index = None;
    unsafe {
        get_adapters_addresses(|adapter| {
            let adapter_name = adapter.description();
            if adapter_name.contains(name) {
                index.replace(adapter.if_index());
                true
            } else {
                false
            }
        });
    }
    index
}

pub fn get_main_adapter_ip() -> Option<String> {
    let mut ret = None;
    unsafe {
        get_adapters_addresses(|adapter| {
            if adapter.is_main_adapter_v4() {
                let ips = adapter.address();
                for ip in ips {
                    if ip.is_ipv4() {
                        ret = Some(ip.to_string());
                        return true;
                    }
                }
            }
            false
        });
    }
    ret
}

pub fn get_main_adapter_gwif() -> Option<(String, u32)> {
    let mut ret = None;
    unsafe {
        get_adapters_addresses(|adapter| {
            if adapter.is_main_adapter_v4() {
                let ips = adapter.gateway();
                for ip in ips {
                    if ip.is_ipv4() {
                        ret = Some((ip.to_string(), adapter.if_index()));
                        return true;
                    }
                }
            }
            false
        });
    }
    ret
}

pub unsafe fn get_adapters_addresses<F>(mut callback: F) -> bool
where
    F: FnMut(&AdapterAddresses) -> bool,
{
    let mut buffer_length: u32 = 0;
    let status = iphlpapi::GetAdaptersAddresses(
        AF_UNSPEC as u32,
        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut buffer_length as PULONG,
    );
    if status != NO_ERROR && status != ERROR_BUFFER_OVERFLOW {
        log::error!("{}", get_error_message(status));
        return false;
    }
    let mut buffer = vec![0u8; buffer_length as usize];
    let status = iphlpapi::GetAdaptersAddresses(
        AF_UNSPEC as u32,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
        std::ptr::null_mut(),
        buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES,
        &mut buffer_length as PULONG,
    );
    if status != NO_ERROR && status != ERROR_BUFFER_OVERFLOW {
        log::error!("{}", get_error_message(status));
        return false;
    }
    let mut info = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES;
    let mut ret = false;
    while !info.is_null() {
        let adapter = &*info;
        let aa = AdapterAddresses::new(adapter);
        ret = callback(&aa);
        if ret {
            break;
        }
        info = adapter.Next;
    }
    ret
}

fn get_error_message(err_code: u32) -> String {
    const LEN: usize = 256;
    let mut buf = MaybeUninit::<[u16; LEN]>::uninit();

    //SAFETY: name is a allocated on the stack above therefore it must be valid, non-null and
    //aligned for u16
    let first = unsafe { *buf.as_mut_ptr() }.as_mut_ptr();
    //Write default null terminator in case WintunGetAdapterName leaves name unchanged
    unsafe { first.write(0u16) };
    let chars_written = unsafe {
        winbase::FormatMessageW(
            winbase::FORMAT_MESSAGE_FROM_SYSTEM | winbase::FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null(),
            err_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as u32,
            first,
            LEN as u32,
            ptr::null_mut(),
        )
    };

    //SAFETY: first is a valid, non-null, aligned, pointer
    format!(
        "{} ({})",
        unsafe { U16Str::from_ptr(first, chars_written as usize) }.to_string_lossy(),
        err_code
    )
}

pub fn set_dns_server(name_server: String) -> bool {
    unsafe {
        get_adapters_addresses(|adapter| {
            if adapter.is_main_adapter_v4() {
                adapter.set_dns_server(name_server.clone())
            } else {
                false
            }
        })
    }
}

pub fn get_dns_server() -> Option<(String, bool)> {
    unsafe {
        let mut ret = None;
        get_adapters_addresses(|adapter| {
            if adapter.is_main_adapter_v4() {
                let ips = adapter.dns();
                for ip in ips {
                    if ip.is_ipv4() {
                        ret = Some((ip.to_string(), !adapter.is_dns_auto()));
                        return true;
                    }
                }
            }
            false
        });
        ret
    }
}
