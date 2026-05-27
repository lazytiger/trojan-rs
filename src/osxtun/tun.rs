use std::{
    ffi::CStr,
    io::{Error, ErrorKind, Result},
    mem,
    os::fd::RawFd,
    sync::Arc,
};

use async_smoltcp::{Packet, Tun};

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const UTUN_OPT_IFNAME: libc::c_int = 2;
const UTUN_HEADER_SIZE: usize = 4;

#[derive(Clone)]
pub struct OsxTun {
    fd: Arc<Fd>,
    mtu: usize,
    interface_name: String,
}

struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl OsxTun {
    pub fn create(mtu: usize) -> Result<Self> {
        let fd = create_utun_fd()?;
        set_nonblocking(fd)?;
        let interface_name = interface_name(fd)?;
        Ok(Self {
            fd: Arc::new(Fd(fd)),
            mtu,
            interface_name,
        })
    }

    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }
}

impl Tun for OsxTun {
    type Packet = TunPacket;

    fn receive(&self) -> Result<Option<Self::Packet>> {
        let mut buf = vec![0u8; self.mtu + UTUN_HEADER_SIZE];
        let read = unsafe { libc::read(self.fd.0, buf.as_mut_ptr().cast(), buf.len()) };
        if read < 0 {
            let err = Error::last_os_error();
            return if err.kind() == ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(err)
            };
        }
        let read = read as usize;
        if read <= UTUN_HEADER_SIZE {
            return Ok(None);
        }
        buf.drain(..UTUN_HEADER_SIZE);
        buf.truncate(read - UTUN_HEADER_SIZE);
        Ok(Some(TunPacket(buf)))
    }

    fn send(&self, packet: Self::Packet) -> Result<()> {
        let family = match packet.0.first().map(|byte| byte >> 4) {
            Some(4) => libc::AF_INET as u32,
            Some(6) => libc::AF_INET6 as u32,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid ip packet version",
                ))
            }
        };
        let mut buf = Vec::with_capacity(packet.0.len() + UTUN_HEADER_SIZE);
        buf.extend_from_slice(&family.to_be_bytes());
        buf.extend_from_slice(&packet.0);
        let written = unsafe { libc::write(self.fd.0, buf.as_ptr().cast(), buf.len()) };
        if written < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn allocate_packet(&self, len: usize) -> Result<Self::Packet> {
        Ok(TunPacket(vec![0u8; len]))
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

pub struct TunPacket(Vec<u8>);

impl Packet for TunPacket {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn as_ref(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

fn create_utun_fd() -> Result<RawFd> {
    unsafe {
        let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        let mut info: libc::ctl_info = mem::zeroed();
        for (idx, byte) in UTUN_CONTROL_NAME.iter().enumerate() {
            info.ctl_name[idx] = *byte as libc::c_char;
        }
        if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
            let err = Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }

        let mut addr: libc::sockaddr_ctl = mem::zeroed();
        addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0;

        let ret = libc::connect(
            fd,
            (&addr as *const libc::sockaddr_ctl).cast(),
            mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        );
        if ret < 0 {
            let err = Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        Ok(fd)
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

fn interface_name(fd: RawFd) -> Result<String> {
    let mut name = [0u8; 64];
    let mut len = name.len() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    let cstr = CStr::from_bytes_until_nul(&name)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "utun interface name missing nul"))?;
    Ok(cstr.to_string_lossy().into_owned())
}
