use std::{
    convert::TryFrom,
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::AsRawFd,
};

#[allow(dead_code)]
pub fn set_mark<T: AsRawFd>(socket: &T, mark: u8) -> Result<()> {
    let fd = socket.as_raw_fd();
    unsafe {
        let mark = mark as libc::c_int;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const _,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        );
        if ret != 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub fn set_socket_opts<T: AsRawFd>(v4: bool, is_udp: bool, socket: &T) -> Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;
    unsafe {
        // 1. Set IP_TRANSPARENT to allow binding to non-local addresses
        let sol = if v4 { libc::SOL_IP } else { libc::SOL_IPV6 };
        let ret = libc::setsockopt(
            fd,
            sol,
            libc::IP_TRANSPARENT,
            &enable as *const _ as *const _,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(Error::last_os_error());
        }

        if is_udp {
            // 2. Set IP_RECVORIGDSTADDR, IPV6_RECVORIGDSTADDR
            let (sol, opt) = if v4 {
                (libc::SOL_IP, libc::IP_RECVORIGDSTADDR)
            } else {
                (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR)
            };
            let ret = libc::setsockopt(
                fd,
                sol,
                opt,
                &enable as *const _ as *const _,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(Error::last_os_error());
            }
        }
    }

    Ok(())
}

pub fn get_oridst_addr<T>(s: &T) -> Result<SocketAddr>
where
    T: AsRawFd,
{
    let fd = s.as_raw_fd();

    unsafe {
        let mut target_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut target_addr_len = std::mem::size_of_val(&target_addr) as libc::socklen_t;

        let ret = libc::getsockname(
            fd,
            &mut target_addr as *mut _ as *mut _,
            &mut target_addr_len,
        );

        if ret != 0 {
            Err(Error::last_os_error())
        } else {
            // Convert sockaddr_storage to SocketAddr
            sockaddr_to_std(&target_addr)
        }
    }
}

fn get_destination_addr(msg: &libc::msghdr) -> Option<libc::sockaddr_storage> {
    unsafe {
        let mut cmsg: *mut libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let rcmsg = &*cmsg;
            match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
                (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = std::mem::zeroed();

                    std::ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );

                    return Some(dst_addr);
                }
                (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = std::mem::zeroed();

                    std::ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    );

                    return Some(dst_addr);
                }
                _ => {}
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    None
}

pub fn recv_from_with_destination<T: AsRawFd>(
    socket: &T,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut control_buf = [0u8; 64];
        let mut src_addr: libc::sockaddr_storage = std::mem::zeroed();

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_addr as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of_val(&src_addr) as libc::socklen_t;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len() as libc::size_t,
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        msg.msg_control = control_buf.as_mut_ptr() as *mut _;
        // This is f*** s***, some platform define msg_controllen as size_t, some define as u32
        msg.msg_controllen = TryFrom::try_from(control_buf.len())
            .expect("failed to convert usize to msg_controllen");

        let fd = socket.as_raw_fd();
        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 0 {
            return Err(Error::last_os_error());
        }

        let dst_addr = match get_destination_addr(&msg) {
            None => {
                let err = Error::new(
                    ErrorKind::InvalidData,
                    "missing destination address in msghdr",
                );
                return Err(err);
            }
            Some(d) => d,
        };

        Ok((
            ret as usize,
            sockaddr_to_std(&src_addr)?,
            sockaddr_to_std(&dst_addr)?,
        ))
    }
}

fn sockaddr_to_std(saddr: &libc::sockaddr_storage) -> Result<SocketAddr> {
    match saddr.ss_family as libc::c_int {
        libc::AF_INET => unsafe {
            let addr: &libc::sockaddr_in = std::mem::transmute(saddr);
            let addr = SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            );
            Ok(SocketAddr::V4(addr))
        },
        libc::AF_INET6 => unsafe {
            let addr: &libc::sockaddr_in6 = std::mem::transmute(saddr);
            let addr = SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                u32::from_be(addr.sin6_flowinfo),
                u32::from_be(addr.sin6_scope_id),
            );
            Ok(SocketAddr::V6(addr))
        },
        _ => {
            let err = Error::new(
                ErrorKind::InvalidData,
                "family must be either AF_INET or AF_INET6",
            );
            Err(err)
        }
    }
}
