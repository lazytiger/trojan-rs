use std::{io::ErrorKind, sync::Arc};

use wintun::Session;

use async_smoltcp::{Packet, Tun};

#[derive(Clone)]
pub struct Wintun {
    session: Arc<Session>,
}

impl Wintun {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }
}

impl Tun for Wintun {
    type Packet = TunPacket;

    fn receive(&self) -> std::io::Result<Option<Self::Packet>> {
        self.session
            .try_receive()
            .map(|packet| packet.map(|packet| TunPacket(packet)))
            .map_err(|_| ErrorKind::OutOfMemory.into())
    }

    fn send(&self, packet: Self::Packet) -> std::io::Result<()> {
        self.session.send_packet(packet.0);
        Ok(())
    }

    fn allocate_packet(&self, len: usize) -> std::io::Result<Self::Packet> {
        self.session
            .allocate_send_packet(len as u16)
            .map(|packet| TunPacket(packet))
            .map_err(|_| ErrorKind::OutOfMemory.into())
    }
}

pub struct TunPacket(wintun::Packet);

impl Packet for TunPacket {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.bytes_mut()
    }

    fn as_ref(&self) -> &[u8] {
        self.0.bytes()
    }

    fn len(&self) -> usize {
        self.0.bytes().len()
    }
}
