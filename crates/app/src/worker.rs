//! Off-thread work that posts back to the UI's frame loop and wakes the window.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use rune::Waker;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Receives messages from background threads and holds the window's [`Waker`].
pub(crate) struct Inbox<T> {
    tx: UnboundedSender<T>,
    rx: UnboundedReceiver<T>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl<T: Send + 'static> Inbox<T> {
    pub(crate) fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            tx,
            rx,
            waker: Arc::default(),
        }
    }

    pub(crate) fn set_waker(&self, waker: Waker) {
        *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(waker);
    }

    pub(crate) fn poster(&self) -> Poster<T> {
        Poster {
            tx: self.tx.clone(),
            waker: self.waker.clone(),
        }
    }

    pub(crate) fn drain(&mut self) -> Vec<T> {
        let mut out = Vec::new();
        while let Ok(item) = self.rx.try_recv() {
            out.push(item);
        }
        out
    }
}

/// Sends a message to an [`Inbox`] and wakes the window.
pub(crate) struct Poster<T> {
    tx: UnboundedSender<T>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl<T> Clone for Poster<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            waker: self.waker.clone(),
        }
    }
}

impl<T: Send + 'static> Poster<T> {
    pub(crate) fn send(&self, item: T) {
        if self.tx.send(item).is_ok()
            && let Some(wake) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).clone()
        {
            wake();
        }
    }

    pub(crate) fn spawn(
        self,
        name: &str,
        work: impl FnOnce(Poster<T>) + Send + 'static,
    ) -> io::Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || work(self))
    }
}
