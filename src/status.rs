use mio::Poll;

#[derive(Copy, Clone, Debug)]
pub enum ConnStatus {
    Connecting,   //
    Established,  // connection is ok
    PeerClosed,   // peer is closed, sending remaining data
    Shutdown,     // self shutdown now
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
        matches!(self.get_status(), ConnStatus::Shutdown)
    }
    fn is_connecting(&self) -> bool {
        matches!(self.get_status(), ConnStatus::Connecting)
    }
    fn set_status(&mut self, status: ConnStatus);
    fn get_status(&self) -> ConnStatus;
    fn peer_closed(&mut self) {
        match self.get_status() {
            ConnStatus::Established => {
                self.set_status(ConnStatus::PeerClosed);
            }
            ConnStatus::PeerClosed => {}
            _ => {
                log::warn!(
                    "invalid status change from:{:?} to {:?}",
                    self.get_status(),
                    ConnStatus::PeerClosed
                );
            }
        }
    }
    fn established(&mut self) {
        match self.get_status() {
            ConnStatus::Connecting => {
                self.set_status(ConnStatus::Established);
            }
            ConnStatus::Established => {}
            _ => {
                log::warn!(
                    "invalid status change from:{:?} to {:?}",
                    self.get_status(),
                    ConnStatus::PeerClosed
                );
            }
        }
    }
    fn close_conn(&mut self);
    fn shutdown(&mut self) {
        match self.get_status() {
            ConnStatus::Established | ConnStatus::PeerClosed | ConnStatus::Connecting => {
                self.close_conn();
                self.set_status(ConnStatus::Shutdown);
            }
            ConnStatus::Shutdown | ConnStatus::Deregistered => {}
        }
    }
    fn deregister(&mut self, poll: &Poll);
    fn finish_send(&mut self) -> bool;
    fn check_status(&mut self, poll: &Poll) {
        loop {
            match self.get_status() {
                ConnStatus::Established | ConnStatus::Connecting => {}
                ConnStatus::PeerClosed => {
                    if self.finish_send() {
                        self.shutdown();
                        continue;
                    }
                }
                ConnStatus::Shutdown => {
                    self.deregister(poll);
                    self.set_status(ConnStatus::Deregistered);
                }
                ConnStatus::Deregistered => {}
            }
            break;
        }
    }
}
