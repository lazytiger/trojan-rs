use std::io::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use mio::{Evented, Poll, PollOpt, Ready, Registration, Token};
use trust_dns_resolver::Resolver;

pub struct EventedResolver {
    registration: Registration,
    address: Arc<Mutex<Option<IpAddr>>>,
    handle: Option<JoinHandle<()>>,
}

impl EventedResolver {
    pub fn new(mut domain: String) -> EventedResolver {
        if !domain.ends_with('.') {
            domain.push('.');
        }
        let (registration, set_readiness) = Registration::new2();
        let address = Arc::new(Mutex::new(None));
        let address2 = address.clone();
        let handle = std::thread::spawn(move || {
            if let Ok(resolver) = Resolver::from_system_conf() {
                if let Ok(response) = resolver.lookup_ip(domain.as_str()) {
                    let mut address = address2.lock().unwrap();
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
            if let Err(err) = set_readiness.set_readiness(Ready::readable()) {
                log::error!("set readiness failed:{}", err);
            }
        });
        EventedResolver {
            registration,
            address,
            handle: Some(handle),
        }
    }

    pub fn address(&self) -> Option<IpAddr> {
        *self.address.lock().unwrap()
    }
}

impl Evented for EventedResolver {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> Result<(), Error> {
        self.registration.register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> Result<(), Error> {
        self.registration.reregister(poll, token, interest, opts)
    }

    #[allow(deprecated)]
    fn deregister(&self, poll: &Poll) -> Result<(), Error> {
        self.registration.deregister(poll)
    }
}

impl Drop for EventedResolver {
    fn drop(&mut self) {
        //FIXME is this necessary?
        let _ = self.handle.take().unwrap().join();
    }
}
