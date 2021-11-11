use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};

use async_std::channel::{bounded, Receiver, Sender};
use async_std::io::{ReadExt, WriteExt};
use async_std::net::TcpStream;
use bytes::BytesMut;

use crate::config::OPTIONS;
use crate::error::{Result, TrojanError};
use crate::proto::{to_u16, DOMAIN, IPV4, IPV6};
use crate::proto::{UdpAssociate, MAX_PACKET_SIZE};

pub type RemoteClientDataType = (usize, [u8; MAX_PACKET_SIZE], SocketAddr);

pub struct RemoteClient {
    address: SocketAddr,
    receiver: Receiver<RemoteClientDataType>,
    sender: Sender<RemoteClientDataType>,
    response_sender: Sender<RemoteClientDataType>,
}

impl RemoteClient {
    pub fn new(address: SocketAddr, response_sender: Sender<RemoteClientDataType>) -> RemoteClient {
        let (sender, receiver) = bounded(OPTIONS.max_channel_buffer);
        RemoteClient {
            address,
            receiver,
            sender,
            response_sender,
        }
    }

    pub async fn start() {
        let conn = TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await;
        if let Err(err) = conn {}
    }

    async fn send(&self, mut conn: TcpStream) {
        let mut header = BytesMut::new();
        loop {
            if let Err(err) = Self::send_once(&mut header, &mut conn, &self.receiver).await {
                Self::close(conn);
                log::warn!("send udp request to remote failed:{}, quit now", err);
                break;
            }
        }
    }

    async fn send_once(
        header: &mut BytesMut,
        conn: &mut TcpStream,
        receiver: &Receiver<RemoteClientDataType>,
    ) -> Result<()> {
        let (size, buffer, dst_addr) = receiver.recv().await?;
        UdpAssociate::generate(header, &dst_addr, size as u16);
        conn.write_all(header.as_ref()).await?;
        conn.write_all(&buffer[..size]).await?;
        Ok(())
    }

    async fn recv(&self, mut conn: TcpStream) {
        loop {
            if let Err(err) = Self::recv_once(&mut conn, &self.response_sender).await {
                Self::close(conn);
                self.receiver.close();
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

    async fn recv_once(conn: &mut TcpStream, sender: &Sender<RemoteClientDataType>) -> Result<()> {
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        conn.read_exact(&mut buffer[..1]).await?;
        let atype = buffer[0];
        let addr = match atype {
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
        sender.send((length, buffer, addr)).await?;
        Ok(())
    }

    pub fn send_data(&self, data: RemoteClientDataType) -> bool {
        if let Err(err) = self.sender.try_send(data) {
            err.is_full()
        } else {
            true
        }
    }
}
