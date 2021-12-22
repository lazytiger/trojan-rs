use smoltcp::iface::SocketHandle;
use std::{
    collections::HashMap,
    sync::Arc,
    task::{Wake, Waker},
};

#[derive(Clone, Copy, Debug)]
pub struct Event(u8);

impl Event {
    pub fn rx() -> Event {
        Event(1)
    }

    pub fn tx() -> Event {
        Event(2)
    }

    pub fn readable(&self) -> bool {
        self.0 & Self::rx().0 != 0
    }

    pub fn writable(&self) -> bool {
        self.0 & Self::tx().0 != 0
    }

    fn add(&mut self, event: Event) {
        self.0 |= event.0;
    }
}

struct TunWaker {
    event: Event,
    handle: SocketHandle,
    handles: Arc<HashMap<SocketHandle, Event>>,
}

impl Wake for TunWaker {
    fn wake(self: Arc<Self>) {
        log::info!("handle:{} waked", self.handle);
        let mut handles = self.handles.clone();
        let handles = unsafe { Arc::get_mut_unchecked(&mut handles) };
        handles
            .entry(self.handle)
            .or_insert(Event(0))
            .add(self.event);
    }
}

impl TunWaker {
    fn waker(
        event: Event,
        handle: SocketHandle,
        handles: Arc<HashMap<SocketHandle, Event>>,
    ) -> Waker {
        let waker = TunWaker {
            handle,
            event,
            handles,
        };
        Waker::from(Arc::new(waker))
    }
}

pub struct Wakers {
    udp_handles: Arc<HashMap<SocketHandle, Event>>,
    tcp_handles: Arc<HashMap<SocketHandle, Event>>,
    wakers: HashMap<SocketHandle, (Waker, Waker)>,
}

impl Wakers {
    pub fn new() -> Self {
        Self {
            udp_handles: Arc::new(Default::default()),
            tcp_handles: Arc::new(Default::default()),
            wakers: Default::default(),
        }
    }
    pub fn get_udp_wakers(&mut self, handle: SocketHandle) -> (&Waker, &Waker) {
        if self.wakers.get(&handle).is_none() {
            let rx = TunWaker::waker(Event::rx(), handle, self.udp_handles.clone());
            let tx = TunWaker::waker(Event::tx(), handle, self.udp_handles.clone());
            self.wakers.insert(handle, (rx, tx));
        }
        let (rx, tx) = self.wakers.get(&handle).unwrap();
        (rx, tx)
    }

    pub fn get_tcp_wakers(&mut self, handle: SocketHandle) -> (&Waker, &Waker) {
        if self.wakers.get(&handle).is_none() {
            let rx = TunWaker::waker(Event::rx(), handle, self.tcp_handles.clone());
            let tx = TunWaker::waker(Event::tx(), handle, self.tcp_handles.clone());
            self.wakers.insert(handle, (rx, tx));
        }
        let (rx, tx) = self.wakers.get(&handle).unwrap();
        (rx, tx)
    }

    pub fn clear(&mut self) {
        unsafe {
            Arc::get_mut_unchecked(&mut self.udp_handles).clear();
            Arc::get_mut_unchecked(&mut self.tcp_handles).clear();
        }
    }

    pub fn get_tcp_handles(&self) -> Arc<HashMap<SocketHandle, Event>> {
        self.tcp_handles.clone()
    }

    pub fn get_udp_handles(&self) -> Arc<HashMap<SocketHandle, Event>> {
        self.udp_handles.clone()
    }
}
