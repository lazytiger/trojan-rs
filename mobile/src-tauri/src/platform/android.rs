use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    mem::ManuallyDrop,
    ops::Deref,
    os::fd::{FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LockResult, RwLock, RwLockReadGuard, RwLockWriteGuard,
    },
    thread::JoinHandle,
};

use smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};

use async_smoltcp::{Packet as _, Tun};
use jni::{
    objects::{JClass, JObject, JString},
    sys::{jboolean, jint},
    JNIEnv, JavaVM,
};

use crate::{
    emit_event, types,
    types::{EventType, VpnError, VpnStatus},
};

struct AndroidContext {
    jvm: JavaVM,
    running: Arc<AtomicBool>,
    dns: String,
    fd: i32,
    handle: Option<JoinHandle<()>>,
}

unsafe impl Sync for AndroidContext {}

unsafe impl Send for AndroidContext {}

lazy_static::lazy_static! {
    static ref CONTEXT:RwLock<Option<AndroidContext>> = RwLock::new(None);
}

fn get_context<'a>() -> Result<
    (
        &'a AndroidContext,
        LockResult<RwLockReadGuard<'a, Option<AndroidContext>>>,
    ),
    VpnError,
> {
    let lock = CONTEXT.read();
    let context = lock
        .as_ref()
        .map_err(|e| VpnError::RLock(e.to_string()))
        .map(|context| -> Result<&'a AndroidContext, VpnError> {
            unsafe { std::mem::transmute(context.as_ref().ok_or(VpnError::NoPlatformContext)) }
        })??;
    Ok((context, lock))
}

fn get_mut_context<'a>() -> Result<
    (
        &'a mut AndroidContext,
        LockResult<RwLockWriteGuard<'a, Option<AndroidContext>>>,
    ),
    VpnError,
> {
    let mut lock = CONTEXT.write();
    let context = lock
        .as_mut()
        .map_err(|e| VpnError::WLock(e.to_string()))
        .map(|context| -> Result<&'a mut AndroidContext, VpnError> {
            unsafe { std::mem::transmute(context.as_mut().ok_or(VpnError::NoPlatformContext)) }
        })??;
    Ok((context, lock))
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_proxy_mobile_MainActivity_00024Companion_initRust<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
) {
    if let Err(err) = init_rust(env) {
        log::error!("init rust failed:{:?}", err);
    }
}

fn init_rust<'local>(env: JNIEnv<'local>) -> Result<(), VpnError> {
    let jvm = env.get_java_vm()?;
    let mut result = CONTEXT
        .write()
        .map_err(|e| VpnError::WLock(e.to_string()))?;
    result.replace(AndroidContext {
        jvm,
        dns: String::new(),
        running: Arc::new(AtomicBool::new(false)),
        fd: -1,
        handle: None,
    });
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_proxy_mobile_MainActivity_onPermissionResult<'local>(
    _: JNIEnv<'local>,
    _: JObject<'local>,
    granted: jboolean,
) {
    log::info!("onPermissionResult:{}", granted);
    if let Err(err) = crate::emit_event(EventType::PermissionResult, granted != 0) {
        log::error!("onPermissionResult failed:{:?}", err);
    }
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_proxy_mobile_TrojanProxy_onStart<'local>(
    mut env: JNIEnv<'local>,
    _: JObject<'local>,
    fd: jint,
    dns: JObject<'local>,
) {
    let dns: JString<'local> = dns.into();
    let dns = env.get_string(&dns).unwrap();
    if let Err(err) = on_vpn_start(fd, dns.to_string_lossy().to_string()) {
        log::error!("onStart failed:{:?}", err);
    }
}

fn on_vpn_start(fd: i32, dns: String) -> Result<(), VpnError> {
    let (context, lock) = get_mut_context()?;
    context.fd = fd;
    context.running = Arc::new(AtomicBool::new(true));
    context.dns = dns;
    drop(lock);
    start_vpn_process()
}

pub fn start_vpn_process() -> Result<(), VpnError> {
    let (context, lock) = get_mut_context()?;
    let fd = context.fd;
    let running = context.running.clone();
    let dns = context.dns.clone();
    if running.load(Ordering::SeqCst) && context.handle.is_none() {
        let handle = std::thread::spawn(move || {
            if let Err(err) = std::panic::catch_unwind(|| {
                if let Err(err) = crate::process_vpn(fd, dns, running) {
                    log::error!("process vpn failed:{:?}", err);
                }
            }) {
                log::error!("uncaught exception:{:?}", err);
                if let Err(err) = emit_event(EventType::StatusChanged, VpnStatus::ProcessExit) {
                    log::error!("emit status changed failed:{:?}", err);
                }
            }
            let (context, lock) = get_mut_context().unwrap();
            context.handle.take();
            drop(lock);
        });
        context.handle.replace(handle);
        emit_event(EventType::StatusChanged, VpnStatus::VpnStart)?;
        log::error!("vpn process started");
    }
    drop(lock);
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_proxy_mobile_TrojanProxy_onStop<'local>(
    _: JNIEnv<'local>,
    _: JObject<'local>,
) {
    if let Err(err) = on_vpn_stop() {
        log::error!("call onStop failed:{:?}", err);
    }
}

fn on_vpn_stop() -> Result<(), VpnError> {
    log::error!("vpn process stopped");
    let (context, lock) = get_mut_context()?;
    context.fd = -1;
    context.running.store(false, Ordering::SeqCst);
    drop(lock);
    emit_event(EventType::StatusChanged, VpnStatus::VpnStop)
}

#[no_mangle]
pub extern "system" fn Java_com_bmshi_proxy_mobile_TrojanProxy_onNetworkChanged<'local>(
    _: JNIEnv<'local>,
    _: JObject<'local>,
    available: jboolean,
) {
    if let Err(err) = on_network_changed(available != 0) {
        log::error!("call onStop failed:{:?}", err);
    }
}

fn on_network_changed(available: bool) -> Result<(), types::VpnError> {
    emit_event(
        EventType::StatusChanged,
        if available {
            VpnStatus::NetworkAvailable
        } else {
            VpnStatus::NetworkLost
        },
    )
}

pub fn init_log(log_level: &String) {
    let config = android_logger::Config::default();
    let config = match log_level.as_str() {
        "Trace" | "0" => config.with_max_level(log::LevelFilter::Trace),
        "Debug" | "1" => config.with_max_level(log::LevelFilter::Debug),
        "Info" | "2" => config.with_max_level(log::LevelFilter::Info),
        "Warn" | "3" => config.with_max_level(log::LevelFilter::Warn),
        "Error" | "4" => config.with_max_level(log::LevelFilter::Error),
        _ => config.with_max_level(log::LevelFilter::Debug),
    };
    let config = config.with_tag("VPN").format(|f, record| {
        write!(
            f,
            "[{}:{}][{}]{}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            record.args()
        )
    });
    android_logger::init_once(config);
}

pub fn start_vpn(mtu: i32) -> Result<(), VpnError> {
    log::info!("start vpn proxy");
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "startVpn",
        "(I)V",
        &[mtu.into()],
    )?;
    Ok(())
}

pub fn stop_vpn() -> Result<(), VpnError> {
    log::info!("stop vpn proxy");
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    env.call_static_method("com/bmshi/proxy/mobile/MainActivity", "stopVpn", "()V", &[])?;
    Ok(())
}

pub fn check_self_permission(permission: impl AsRef<str>) -> Result<bool, VpnError> {
    log::info!("check self permission:{}", permission.as_ref());
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    let permission = env.new_string(permission)?;
    let ret = env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "checkSelfPermission",
        "(Ljava/lang/String;)Z",
        &[(&permission).into()],
    )?;
    Ok(ret.z()?)
}

pub fn request_permission(permission: impl AsRef<str>) -> Result<(), VpnError> {
    log::info!("request permission:{}", permission.as_ref());
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    let permission = env.new_string(permission)?;
    env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "requestPermission",
        "(Ljava/lang/String;)V",
        &[(&permission).into()],
    )?;
    Ok(())
}

pub fn should_show_permission_rationale(permission: impl AsRef<str>) -> Result<bool, VpnError> {
    log::info!("should show permission rationale:{}", permission.as_ref());
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    let permission = env.new_string(permission)?;
    let ret = env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "shouldShowRequestPermissionRationaleNative",
        "(Ljava/lang/String;)Z",
        &[(&permission).into()],
    )?;
    Ok(ret.z()?)
}

pub fn update_notification(content: impl AsRef<str>) -> Result<(), VpnError> {
    //log::info!("update notification:{}", content.as_ref());
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    let content = env.new_string(content)?;
    env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "updateNotification",
        "(Ljava/lang/String;)V",
        &[(&content).into()],
    )?;
    Ok(())
}

pub fn save_data(key: impl AsRef<str>, content: impl AsRef<str>) -> Result<(), VpnError> {
    log::info!("save data:{} - {}", key.as_ref(), content.as_ref());
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    let content = env.new_string(content)?;
    let key = env.new_string(key)?;
    env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "saveData",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[(&key).into(), (&content).into()],
    )?;
    Ok(())
}

pub fn load_data(key: impl AsRef<str>) -> Result<String, VpnError> {
    log::info!("load data:{}", key.as_ref());
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    let key = env.new_string(key)?;
    let ret = env.call_static_method(
        "com/bmshi/proxy/mobile/MainActivity",
        "loadData",
        "(Ljava/lang/String;)Ljava/lang/String;",
        &[(&key).into()],
    )?;

    let value: JString = ret.l()?.into();
    let value = env.get_string(&value)?.to_string_lossy().to_string();

    Ok(value)
}

#[allow(unused)]
pub fn sync_data() -> Result<(), VpnError> {
    log::info!("sync data");
    let (context, lock) = get_context()?;
    let mut env = context.jvm.attach_current_thread()?;
    drop(lock);
    env.call_static_method("com/bmshi/proxy/mobile/TrojanProxy", "syncData", "()V", &[])?;
    Ok(())
}

pub struct Session {
    file: ManuallyDrop<File>,
    mtu: usize,
    show_info: bool,
}

pub struct Packet {
    data: Vec<u8>,
}

impl Session {
    pub fn new(fd: i32, mtu: usize, show_info: bool) -> Self {
        unsafe {
            let fd = OwnedFd::from_raw_fd(fd);
            let file = fd.into();
            Self {
                file: ManuallyDrop::new(file),
                mtu,
                show_info,
            }
        }
    }
}

impl Tun for Session {
    type Packet = Packet;

    fn receive(&self) -> std::io::Result<Option<Self::Packet>> {
        let mut packet = Packet::new(self.mtu);
        let mut file = self.file.deref();
        match file.read(packet.as_mut()) {
            Ok(0) => {
                log::error!("end of file");
                Err(ErrorKind::BrokenPipe.into())
            }
            Ok(n) => {
                packet.set_len(n);
                Ok(Some(packet))
            }
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted =>
            {
                Ok(None)
            }
            Err(err) => {
                log::error!("read file failed:{:?}", err);
                Err(err)
            }
        }
    }
    fn send(&self, packet: Self::Packet) -> std::io::Result<()> {
        let mut file = self.file.deref();
        if let Err(err) = file.write_all(packet.as_ref()) {
            log::error!("send packet failed:{}", err);
            return Err(err);
        } else if self.show_info {
            if let Err(err) = packet.info() {
                log::error!("parse return packet failed:{:?}", err);
            }
        }
        Ok(())
    }
    fn allocate_packet(&self, len: usize) -> std::io::Result<Self::Packet> {
        Ok(Packet::new(len))
    }
}

impl Packet {
    pub fn new(size: usize) -> Self {
        let data = vec![0u8; size];
        Self { data }
    }

    fn set_len(&mut self, len: usize) {
        unsafe {
            self.data.set_len(len);
        }
    }

    fn info(&self) -> types::Result<()> {
        let (dst_addr, src_addr, payload, protocol) = match IpVersion::of_packet(self.as_ref())? {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_checked(self.as_ref())?;
                let dst_addr = packet.dst_addr();
                let src_addr = packet.src_addr();
                (
                    IpAddress::Ipv4(dst_addr),
                    IpAddress::Ipv4(src_addr),
                    packet.payload(),
                    packet.next_header(),
                )
            }
            IpVersion::Ipv6 => {
                let packet = Ipv6Packet::new_checked(self.as_ref())?;
                let dst_addr = packet.dst_addr();
                let src_addr = packet.src_addr();
                (
                    IpAddress::Ipv6(dst_addr),
                    IpAddress::Ipv6(src_addr),
                    packet.payload(),
                    packet.next_header(),
                )
            }
        };
        let (dst_port, src_port, payload) = match protocol {
            IpProtocol::Udp => {
                let packet = UdpPacket::new_checked(payload)?;
                (packet.dst_port(), packet.src_port(), packet.payload())
            }
            IpProtocol::Tcp => {
                let packet = TcpPacket::new_checked(payload)?;
                (packet.dst_port(), packet.src_port(), packet.payload())
            }
            _ => return Ok(()),
        };
        log::info!(
            "send packet {} {}:{} - {}:{} {} bytes",
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            payload.len()
        );
        Ok(())
    }
}

impl async_smoltcp::Packet for Packet {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
    fn len(&self) -> usize {
        self.data.len()
    }
}

impl From<Vec<u8>> for Packet {
    fn from(value: Vec<u8>) -> Self {
        Self { data: value }
    }
}
