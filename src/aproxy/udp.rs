use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_std::channel::{Receiver, Sender};
use async_std::io::{ReadExt, WriteExt};
use async_std::net::{TcpStream, UdpSocket};
use async_std::task;
use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection};

use crate::config::OPTIONS;
use crate::error::{Result, TrojanError};
use crate::proto::{to_u16, DOMAIN, IPV4, IPV6};
use crate::proto::{UdpAssociate, MAX_PACKET_SIZE};
use crate::proxy::new_socket;

pub type UdpRequestType = (usize, [u8; MAX_PACKET_SIZE], SocketAddr);
pub type UdpResponseType = (usize, [u8; MAX_PACKET_SIZE], SocketAddr, SocketAddr);

pub async fn start(
    address: SocketAddr,
    receiver: Receiver<UdpRequestType>,
    sender: Sender<UdpResponseType>,
    client: ClientConnection,
) {
    let conn = TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await;
    if let Err(err) = conn {
        log::error!("connect to backend:{:?} failed:{}", OPTIONS.back_addr, err);
        receiver.close();
        return;
    }
    let conn = conn.unwrap();
    let client = Arc::new(Mutex::new(client));
    task::spawn(send(conn.clone(), receiver, client.clone()));
    recv(conn, sender, address, client.clone()).await;
    log::warn!("udp connection from:{} closed", address);
}

async fn send(
    mut conn: TcpStream,
    receiver: Receiver<UdpRequestType>,
    client: Arc<Mutex<ClientConnection>>,
) {
    let mut header = BytesMut::new();
    loop {
        if let Err(err) = send_once(&mut header, &mut conn, &receiver, client.clone()).await {
            close(conn);
            log::warn!("send udp request to remote failed:{}, quit now", err);
            break;
        }
    }
}

async fn send_once(
    header: &mut BytesMut,
    conn: &mut TcpStream,
    receiver: &Receiver<UdpRequestType>,
    client: Arc<Mutex<ClientConnection>>,
) -> Result<()> {
    let (size, mut buffer, dst_addr) = receiver.recv().await?;
    header.clear();
    UdpAssociate::generate(header, &dst_addr, size as u16);
    let mut data: Vec<u8> = Vec::new();
    {
        let mut locker = client.lock()?;
        locker.writer().write_all(header.as_ref())?;
        locker.writer().write_all(&buffer[..size])?;

        while locker.wants_write() {
            locker.write_tls(&mut data)?;
        }
    }
    conn.write_all(data.as_slice()).await?;
    Ok(())
}

async fn recv(
    mut conn: TcpStream,
    sender: Sender<UdpResponseType>,
    address: SocketAddr,
    client: Arc<Mutex<ClientConnection>>,
) {
    loop {
        if let Err(err) = recv_once(&mut conn, &sender, address, client.clone()).await {
            close(conn);
            //receiver.close();
            log::warn!("receive udp response from remote failed:{}, quit now", err);
            break;
        }
    }
}

fn close(conn: TcpStream) {
    if let Err(err) = conn.shutdown(Shutdown::Both) {
        log::warn!("shutdown udp reading process failed:{}", err);
    }
}

async fn recv_once(
    conn: &mut TcpStream,
    sender: &Sender<UdpResponseType>,
    src_addr: SocketAddr,
    client: Arc<Mutex<ClientConnection>>,
) -> Result<()> {
    let mut buffer = [0u8; MAX_PACKET_SIZE];
    conn.read_exact(&mut buffer[..1]).await?;
    let atype = buffer[0];
    let dst_addr = match atype {
        IPV4 => {
            conn.read_exact(&mut buffer[..6]).await?;
            let port = to_u16(&buffer[4..]);
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(buffer[0], buffer[1], buffer[2], buffer[3]),
                port,
            ))
        }
        IPV6 => {
            conn.read_exact(&mut buffer[..18]).await?;
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(
                    to_u16(&buffer),
                    to_u16(&buffer[2..]),
                    to_u16(&buffer[4..]),
                    to_u16(&buffer[6..]),
                    to_u16(&buffer[8..]),
                    to_u16(&buffer[10..]),
                    to_u16(&buffer[12..]),
                    to_u16(&buffer[14..]),
                ),
                to_u16(&buffer[16..]),
                0,
                0,
            ))
        }
        DOMAIN => {
            log::error!("domain address type found in udp response");
            return Err(TrojanError::InvalidProtocol);
        }
        _ => {
            log::error!("invalid address type:{} found in udp response", atype);
            return Err(TrojanError::InvalidProtocol);
        }
    };
    conn.read_exact(&mut buffer[..4]).await?;
    let length = to_u16(&buffer) as usize;
    if length >= MAX_PACKET_SIZE {
        log::error!(
            "udp response packet size:{} exceeds limit:{}",
            length,
            MAX_PACKET_SIZE
        );
        return Err(TrojanError::InvalidProtocol);
    }
    conn.read_exact(&mut buffer[..length]).await?;
    sender.send((length, buffer, src_addr, dst_addr)).await?;
    Ok(())
}

pub async fn start_proxy(receiver: Receiver<UdpResponseType>) {
    let mut dst_sockets = HashMap::new();
    loop {
        if let Err(err) = do_proxy(&receiver, &mut dst_sockets).await {
            log::error!("proxy data failed:{}", err);
        }
        //TODO check timeout
    }
}

async fn do_proxy(
    receiver: &Receiver<UdpResponseType>,
    dst_sockets: &mut HashMap<SocketAddr, (UdpSocket, Instant)>,
) -> Result<()> {
    let (size, buffer, src_addr, dst_addr) = receiver.recv().await?;
    let socket = if let Some((socket, time)) = dst_sockets.get_mut(&dst_addr) {
        *time = Instant::now();
        socket
    } else {
        let socket: std::net::UdpSocket = new_socket(dst_addr, true).unwrap().into();
        let socket: UdpSocket = socket.into();
        dst_sockets.insert(dst_addr, (socket, Instant::now()));
        let (socket, _) = dst_sockets.get_mut(&dst_addr).unwrap();
        socket
    };
    socket.send_to(&buffer[..size], src_addr).await?;
    Ok(())
}
