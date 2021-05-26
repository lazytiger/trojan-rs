use std::{net::IpAddr, sync::Arc};

use mio::{Poll, Token, Waker};
use std::sync::mpsc::{channel, Receiver, Sender};
use trust_dns_resolver::Resolver;

pub struct EventedResolver {
    waker: Arc<Waker>,
    receiver: Receiver<(Token, Option<IpAddr>)>,
    sender: Sender<(Token, Option<IpAddr>)>,
}

impl EventedResolver {
    pub fn resolve(&self, mut domain: String, token: Token) {
        if !domain.ends_with('.') {
            domain.push('.');
        }
        let sender = self.sender.clone();
        let waker = self.waker.clone();
        rayon::spawn(move || {
            let mut address = None;
            if let Ok(resolver) = Resolver::from_system_conf() {
                if let Ok(response) = resolver.lookup_ip(domain.as_str()) {
                    for addr in response.iter() {
                        if address.is_none() || addr.is_ipv4() {
                            address.replace(addr);
                        }
                        if address.as_ref().unwrap().is_ipv4() {
                            break;
                        }
                    }
                }
            }
            if let Err(err) = sender.send((token, address)) {
                log::error!("send resolver result failed:{:?}", err);
            } else if let Err(err) = waker.wake() {
                log::error!("wake failed {}", err);
            }
        });
    }

    pub fn consume<F: FnMut((Token, Option<IpAddr>))>(&self, f: F) {
        self.receiver.try_iter().for_each(f);
    }

    pub fn new(poll: &Poll, token: Token) -> Self {
        let (sender, receiver) = channel();
        let waker = Arc::new(Waker::new(poll.registry(), token).unwrap());
        Self {
            sender,
            receiver,
            waker,
        }
    }
}
