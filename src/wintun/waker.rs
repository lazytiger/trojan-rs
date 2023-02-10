use std::{
    collections::HashMap,
    sync::Arc,
    task::{Wake, Waker},
};

use crossbeam::channel::{Receiver, Sender};
use smoltcp::iface::SocketHandle;

#[derive(Clone, Copy, Debug)]
pub struct Event(u8);

impl Event {
    pub fn rx() -> Event {
        Event(1)
    }

    pub fn tx() -> Event {
        Event(2)
    }

    pub fn is_readable(&self) -> bool {
        self.0 & Self::rx().0 != 0
    }

    pub fn is_writable(&self) -> bool {
        self.0 & Self::tx().0 != 0
    }

    fn add(&mut self, event: Event) {
        self.0 |= event.0;
    }
}

struct TunWaker {
    event: Event,
    handle: SocketHandle,
    sender: Sender<(SocketHandle, Event)>,
}

impl Wake for TunWaker {
    fn wake(self: Arc<Self>) {
        self.sender.send((self.handle, self.event)).unwrap();
    }
}

impl TunWaker {
    fn create(event: Event, handle: SocketHandle, sender: Sender<(SocketHandle, Event)>) -> Waker {
        let waker = Arc::new(TunWaker {
            handle,
            event,
            sender,
        });
        Waker::from(waker)
    }
}

pub struct Wakers {
    wakers: HashMap<SocketHandle, (Waker, Waker)>,
    sender: Sender<(SocketHandle, Event)>,
    receiver: Receiver<(SocketHandle, Event)>,
    dummy: Waker,
}

impl Wakers {
    pub fn new() -> Self {
        let (sender, receiver) = crossbeam::channel::unbounded();
        Self {
            wakers: Default::default(),
            sender,
            receiver,
            dummy: Waker::from(Arc::new(DummyWaker)),
        }
    }
    pub fn get_wakers(&mut self, handle: SocketHandle) -> (&Waker, &Waker) {
        if self.wakers.get(&handle).is_none() {
            let rx = TunWaker::create(Event::rx(), handle, self.sender.clone());
            let tx = TunWaker::create(Event::tx(), handle, self.sender.clone());
            self.wakers.insert(handle, (rx, tx));
        }
        let (rx, tx) = self.wakers.get(&handle).unwrap();
        (rx, tx)
    }
    pub fn get_events(&self) -> HashMap<SocketHandle, Event> {
        let mut events = HashMap::new();
        while let Ok((handle, event)) = self.receiver.try_recv() {
            events.entry(handle).or_insert(event).add(event);
        }
        events
    }
    pub fn get_dummy_waker(&self) -> &Waker {
        &self.dummy
    }
}

struct DummyWaker;

impl Wake for DummyWaker {
    fn wake(self: Arc<Self>) {}
}

pub enum WakerMode {
    Recv,
    Send,
    Both,
    None,
    Dummy,
}
