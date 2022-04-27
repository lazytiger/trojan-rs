use mio::Poll;

#[derive(Copy, Clone, Debug)]
pub enum ConnStatus {
    Connecting,
    //
    Established,
    // connection is ok
    PeerClosed,
    // peer is closed, sending remaining data
    Shutdown,
    // self shutdown now
    Deregistered, // self deregistered
}

pub trait StatusProvider {
    fn deregistered(&self) -> bool {
        matches!(self.get_status(), ConnStatus::Deregistered)
    }
    fn alive(&self) -> bool {
        matches!(
            self.get_status(),
            ConnStatus::PeerClosed | ConnStatus::Established
        )
    }
    fn is_shutdown(&self) -> bool {
        matches!(
            self.get_status(),
            ConnStatus::Shutdown | ConnStatus::Deregistered
        )
    }
    fn is_connecting(&self) -> bool {
        matches!(self.get_status(), ConnStatus::Connecting)
    }
    fn set_status(&mut self, status: ConnStatus);
    fn get_status(&self) -> ConnStatus;
    fn peer_closed(&mut self) {
        match self.get_status() {
            ConnStatus::Established | ConnStatus::Connecting => {
                self.set_status(ConnStatus::PeerClosed);
            }
            _ => {}
        }
    }
    fn established(&mut self) {
        if matches!(self.get_status(), ConnStatus::Connecting) {
            self.set_status(ConnStatus::Established);
        }
    }
    fn close_conn(&mut self) -> bool;
    fn shutdown(&mut self) -> bool {
        match self.get_status() {
            ConnStatus::Established | ConnStatus::PeerClosed | ConnStatus::Connecting => {
                if self.close_conn() {
                    self.set_status(ConnStatus::Shutdown);
                } else {
                    return false;
                }
            }
            ConnStatus::Shutdown | ConnStatus::Deregistered => {}
        }
        true
    }
    fn deregister(&mut self, poll: &Poll) -> bool;
    fn finish_send(&mut self) -> bool;
    fn check_status(&mut self, poll: &Poll) {
        loop {
            match self.get_status() {
                ConnStatus::Established | ConnStatus::Connecting => {}
                ConnStatus::PeerClosed => {
                    if self.finish_send() && self.shutdown() {
                        continue;
                    }
                }
                ConnStatus::Shutdown => {
                    if self.deregister(poll) {
                        self.set_status(ConnStatus::Deregistered);
                    }
                }
                ConnStatus::Deregistered => {}
            }
            break;
        }
    }
}
