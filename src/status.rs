use mio::Poll;

#[derive(Copy, Clone, Debug)]
pub enum ConnStatus {
    Established,  // connection is ok
    PeerClosed,   // peer is closed, sending remaining data
    Shutdown,     // self shutdown now
    Deregistered, // self deregistered
}

pub trait StatusProvider {
    fn deregistered(&self) -> bool {
        matches!(self.get_status(), ConnStatus::Deregistered)
    }
    fn is_shutdown(&self) -> bool {
        matches!(self.get_status(), ConnStatus::Shutdown)
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
                log::error!(
                    "invalid status change from:{:?} to {:?}",
                    self.get_status(),
                    ConnStatus::Established
                );
            }
        }
    }
    fn close_conn(&self);
    fn shutdown(&mut self) {
        match self.get_status() {
            ConnStatus::Established | ConnStatus::PeerClosed => {
                self.close_conn();
                self.set_status(ConnStatus::Shutdown);
            }
            ConnStatus::Shutdown => {}
            _ => {
                log::error!(
                    "invalid status change from:{:?} to {:?}",
                    self.get_status(),
                    ConnStatus::Established
                );
            }
        }
    }
    fn deregister(&mut self, poll: &Poll);
    fn finish_send(&mut self) -> bool;
    fn check_status(&mut self, poll: &Poll) {
        loop {
            match self.get_status() {
                ConnStatus::Established => {}
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
