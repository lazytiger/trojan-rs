use std::{fs::OpenOptions, io::Write, net::SocketAddr, sync::Arc, time::Duration};

use async_smoltcp::{Tun, TunDevice};
use bytes::BytesMut;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    net::TcpStream,
    runtime::Runtime,
    spawn,
    sync::{mpsc::channel, Notify},
    time::{interval, MissedTickBehavior},
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use types::Result;

#[cfg(windows)]
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Condvar, Mutex,
    },
    thread,
};

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, RawFd};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, HANDLE, WAIT_FAILED, WAIT_OBJECT_0},
    System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE},
};
#[cfg(windows)]
use wintool::adapter::get_main_adapter_gwif;
#[cfg(windows)]
use wintun::Adapter;

use crate::{
    awintun::{
        tcp::start_tcp,
        udp::{run_udp_dispatch, start_udp},
    },
    config::OPTIONS,
    proto::{TrojanRequest, UDP_ASSOCIATE},
    types,
};

#[cfg(target_os = "macos")]
use crate::osxtun::{
    route::{build_cleanup_commands, default_gateway, run_commands, RouteConfig, RouteGuard},
    tun::OsxTun,
};
#[cfg(windows)]
use crate::{
    awintun::tun::Wintun,
    types::TrojanError,
    wintun::{apply_ipset, route_add_with_if},
};

mod tcp;
#[cfg(windows)]
mod tun;
mod udp;

#[cfg(windows)]
type PlatformTunReady = WintunReady;
#[cfg(target_os = "macos")]
type PlatformTunReady = OsxTunReady;

#[cfg(windows)]
struct WintunReady {
    wake: Arc<Notify>,
    state: Arc<ReadyState>,
    shutdown_event: HANDLE,
    thread: Option<thread::JoinHandle<()>>,
}

#[cfg(windows)]
struct ReadyState {
    armed: Mutex<bool>,
    shutdown: AtomicBool,
    condvar: Condvar,
}

#[cfg(windows)]
impl WintunReady {
    fn new(session: Arc<wintun::Session>) -> Result<Self> {
        let read_event = session.get_read_wait_event()?;
        let shutdown_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if shutdown_event == 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let wake = Arc::new(Notify::new());
        let state = Arc::new(ReadyState {
            armed: Mutex::new(true),
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
        });
        let thread_wake = wake.clone();
        let thread_state = state.clone();
        let thread = match thread::Builder::new()
            .name("wintun-ready".to_string())
            .spawn(move || {
                let _session = session;
                let handles = [read_event, shutdown_event];

                loop {
                    let result = unsafe {
                        WaitForMultipleObjects(
                            handles.len() as u32,
                            handles.as_ptr(),
                            FALSE,
                            INFINITE,
                        )
                    };
                    match result {
                        WAIT_OBJECT_0 => {
                            {
                                let mut armed = thread_state
                                    .armed
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner());
                                *armed = false;
                            }
                            thread_wake.notify_one();

                            let mut armed = thread_state
                                .armed
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            while !*armed && !thread_state.shutdown.load(Ordering::Acquire) {
                                armed = thread_state
                                    .condvar
                                    .wait(armed)
                                    .unwrap_or_else(|error| error.into_inner());
                            }
                            if thread_state.shutdown.load(Ordering::Acquire) {
                                break;
                            }
                        }
                        result if result == WAIT_OBJECT_0 + 1 => break,
                        WAIT_FAILED => {
                            log::error!(
                                "wait wintun read event failed: {}",
                                std::io::Error::last_os_error()
                            );
                            break;
                        }
                        other => {
                            log::error!(
                                "wait wintun read event returned unexpected value: {other}"
                            );
                            break;
                        }
                    }
                }
            }) {
            Ok(thread) => thread,
            Err(error) => {
                unsafe { CloseHandle(shutdown_event) };
                return Err(error.into());
            }
        };

        Ok(Self {
            wake,
            state,
            shutdown_event,
            thread: Some(thread),
        })
    }

    async fn readable(&self) -> std::io::Result<()> {
        self.wake.notified().await;
        Ok(())
    }

    fn arm(&self) {
        let mut armed = self
            .state
            .armed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !*armed {
            *armed = true;
            self.state.condvar.notify_one();
        }
    }
}

#[cfg(windows)]
impl Drop for WintunReady {
    fn drop(&mut self) {
        self.state.shutdown.store(true, Ordering::Release);
        if unsafe { SetEvent(self.shutdown_event) } == FALSE {
            log::error!(
                "set wintun readiness shutdown event failed: {}",
                std::io::Error::last_os_error()
            );
        }
        self.state.condvar.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if unsafe { CloseHandle(self.shutdown_event) } == FALSE {
            log::error!(
                "close wintun readiness shutdown event failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(target_os = "macos")]
struct RawTunFd(RawFd);

#[cfg(target_os = "macos")]
impl AsRawFd for RawTunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(target_os = "macos")]
struct OsxTunReady {
    fd: tokio::io::unix::AsyncFd<RawTunFd>,
}

#[cfg(target_os = "macos")]
impl OsxTunReady {
    fn new(tun: &OsxTun) -> std::io::Result<Self> {
        Ok(Self {
            fd: tokio::io::unix::AsyncFd::new(RawTunFd(tun.raw_fd()))?,
        })
    }

    async fn readable(&self) -> std::io::Result<()> {
        let mut guard = self.fd.readable().await?;
        guard.clear_ready();
        Ok(())
    }

    fn arm(&self) {}
}

async fn wait_stack_delay(delay: Option<Duration>) {
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    } else {
        std::future::pending::<()>().await;
    }
}

pub async fn init_tls_conn(
    connector: TlsConnector,
    server_name: ServerName<'static>,
) -> types::Result<TlsStream<TcpStream>> {
    let stream = tokio::net::TcpStream::connect((
        OPTIONS.wintun_args().hostname.as_str(),
        OPTIONS.wintun_args().port,
    ))
    .await?;
    let conn = connector.connect(server_name, stream).await?;
    Ok(conn)
}

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
}

#[cfg(windows)]
async fn async_run() -> Result<()> {
    log::info!("dll:{}", OPTIONS.wintun_args().wintun);
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let adapter = Adapter::create(&wintun, "trojan", OPTIONS.wintun_args().name.as_str(), None)?;
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    let (main_gw, main_index) = if let Some((main_gw, main_index)) = get_main_adapter_gwif() {
        log::warn!(
            "main adapter gateway is {}, main adapter index is :{}",
            main_gw,
            main_index
        );
        let gw: Ipv4Addr = main_gw.parse()?;
        if let Some(SocketAddr::V4(v4)) = &OPTIONS.back_addr {
            let index: u32 = (*v4.ip()).into();
            route_add_with_if(index, !0, gw.into(), main_index)?;
        }
        (gw, main_index)
    } else {
        log::error!("main adapter gateway not found");
        return Err(TrojanError::MainAdapterNotFound);
    };
    let index = adapter.get_adapter_index()?;
    if let Some(file) = &OPTIONS.wintun_args().route_ipset {
        apply_ipset(file, index, main_gw, main_index)?;
    }

    let server_addr = *OPTIONS.back_addr.as_ref().unwrap();
    let mtu = OPTIONS.wintun_args().mtu;
    let tun_ready = PlatformTunReady::new(session.clone())?;
    let mut device = TunDevice::new(Wintun::new(mtu, session));
    device.add_black_ip(server_addr.ip());
    run_device(device, tun_ready).await
}

#[cfg(target_os = "macos")]
async fn async_run() -> Result<()> {
    let server_addr = *OPTIONS.back_addr.as_ref().unwrap();
    let server_ip = match server_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(types::TrojanError::Custom(
                "osxtun only supports IPv4 server route now".to_string(),
            ))
        }
    };
    let mtu = OPTIONS.wintun_args().mtu;
    let tun = OsxTun::create(mtu)?;
    let tun_ready = PlatformTunReady::new(&tun)?;
    let interface = tun.interface_name().to_string();
    let route_config = RouteConfig {
        interface: interface.clone(),
        gateway: default_gateway()?,
        server_ip,
        tun_addr: "10.255.0.2".parse()?,
        tun_peer: "10.255.0.1".parse()?,
        mtu,
    };
    let _ = run_commands(&build_cleanup_commands(&route_config));
    let _route_guard = RouteGuard::apply(route_config)?;
    log::warn!(
        "osxtun started on {} with server:{}",
        interface,
        server_addr
    );
    let mut device = TunDevice::new(tun);
    device.add_black_ip(server_addr.ip());
    device.allow_private(true);
    run_device(device, tun_ready).await
}

async fn run_device<T>(mut device: TunDevice<'_, T>, tun_ready: PlatformTunReady) -> Result<()>
where
    T: Tun + Clone,
{
    let server_name: ServerName = OPTIONS.wintun_args().hostname.as_str().try_into()?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut header = BytesMut::new();
    TrojanRequest::generate(&mut header, UDP_ASSOCIATE, &empty);
    let udp_header = Arc::new(header);

    let (data_sender, data_receiver) = channel(128);
    let (socket_sender, socket_receiver) = channel(128);
    let (close_sender, close_receiver) = channel(128);
    let connector = TlsConnector::from(config);
    spawn(run_udp_dispatch(
        data_receiver,
        socket_receiver,
        server_name.clone(),
        connector.clone(),
        OPTIONS.wintun_args().mtu,
        udp_header.clone(),
        close_receiver,
        close_sender.clone(),
    ));
    let device_wake = device.notifier();
    let mut speed_tick = interval(Duration::from_secs(1));
    speed_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    speed_tick.tick().await;
    let mut maintenance_tick = interval(Duration::from_secs(1));
    maintenance_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    maintenance_tick.tick().await;

    loop {
        let stack_delay = device.poll_delay();
        let poll_stack = tokio::select! {
            result = tun_ready.readable() => {
                result?;
                true
            }
            _ = device_wake.notified() => true,
            _ = wait_stack_delay(stack_delay) => true,
            _ = speed_tick.tick() => {
                let (rx_speed, tx_speed) = device.calculate_speed();
                log::info!(
                    "current speed - rx:{:.4}KB/s, tx:{:.4}/KB/s",
                    rx_speed,
                    tx_speed
                );
                let mut file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(OPTIONS.wintun_args().status_file.as_str())?;
                write!(&mut file, "{:.4} {:.4}", rx_speed, tx_speed)?;
                false
            }
            _ = maintenance_tick.tick() => {
                device.maintenance();
                false
            }
        };

        if !poll_stack {
            continue;
        }

        let (tcp_streams, udp_sockets) = device.poll();
        tun_ready.arm();
        for stream in tcp_streams {
            log::info!(
                "accept tcp {} - {}",
                stream.local_addr(),
                stream.peer_addr()
            );
            spawn(start_tcp(stream, connector.clone(), server_name.clone()));
        }
        for socket in udp_sockets {
            log::info!("accept udp to:{}", socket.peer_addr());
            let writer = Arc::new(socket.writer());
            let _ = socket_sender.send(writer).await;
            spawn(start_udp(socket, data_sender.clone(), close_sender.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn awintun_loop_does_not_use_fixed_poll_sleep() {
        let source = include_str!("mod.rs");
        let fixed_poll_sleep = concat!("sleep", "(Duration::from_millis(1))");

        assert!(
            !source.contains(fixed_poll_sleep),
            "awintun should wake from tun readiness, device notifications, or smoltcp timers instead of fixed 1ms polling"
        );
    }
}
