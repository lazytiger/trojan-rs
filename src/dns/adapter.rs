#![allow(dead_code)]

use std::{mem::MaybeUninit, ptr};

use widestring::U16Str;
use winapi::{
    shared::{
        minwindef::{PULONG, ULONG},
        ntdef::{CHAR, LANG_NEUTRAL, SUBLANG_DEFAULT},
        winerror,
    },
    um::{iphlpapi, iptypes::IP_ADAPTER_INFO, winbase, winnt::MAKELANGID},
};

pub fn get_adapter_ip(name: &str) -> Option<String> {
    let mut ret = None;
    unsafe {
        get_adapters(|adapter| {
            let adapter_name = get_string(&adapter.Description);
            if adapter_name.contains(name) {
                let ip = get_string(&adapter.IpAddressList.IpAddress.String);
                if ip != "0.0.0.0" {
                    ret = Some(ip);
                }
                true
            } else {
                false
            }
        });
    }
    ret
}

pub fn get_adapter_index(name: &str) -> Option<u32> {
    let mut index = None;
    unsafe {
        get_adapters(|adapter| {
            let adapter_name = get_string(&adapter.Description);
            if adapter_name.contains(name) {
                index.replace(adapter.Index);
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
        get_adapters(|adapter| {
            let ip = get_string(&adapter.GatewayList.IpAddress.String);
            if ip.is_empty() {
                false
            } else {
                let ip = get_string(&adapter.IpAddressList.IpAddress.String);
                ret = Some(ip);
                true
            }
        })
    }
    ret
}

pub fn get_main_adapter_gwif() -> Option<(String, u32)> {
    let mut ret = None;
    unsafe {
        get_adapters(|adapter| {
            let ip = get_string(&adapter.GatewayList.IpAddress.String);
            ret = Some((ip.clone(), adapter.Index));
            !ip.is_empty()
        })
    }
    ret
}

unsafe fn get_adapters<F>(mut callback: F)
where
    F: FnMut(&IP_ADAPTER_INFO) -> bool,
{
    let mut buffer_length: u32 = 0;
    let result = iphlpapi::GetAdaptersInfo(std::ptr::null_mut(), &mut buffer_length as PULONG);
    if result != winerror::NOERROR as ULONG && result != winerror::ERROR_BUFFER_OVERFLOW {
        panic!("{}", get_error_message(result));
    }
    let mut buffer = vec![0u8; buffer_length as usize];
    let result = iphlpapi::GetAdaptersInfo(
        buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO,
        &mut buffer_length as PULONG,
    );
    if result != winerror::NOERROR as ULONG && result != winerror::ERROR_BUFFER_OVERFLOW {
        panic!("{}", get_error_message(result));
    }
    let mut info = buffer.as_ptr() as *const IP_ADAPTER_INFO;
    while !info.is_null() {
        let adapter = &*info;
        if callback(adapter) {
            break;
        }
        info = adapter.Next;
    }
}

fn get_string(s: &[CHAR]) -> String {
    String::from_utf8(
        s.iter()
            .map_while(|c| if *c == 0 { None } else { Some(*c as u8) })
            .collect(),
    )
    .unwrap()
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
