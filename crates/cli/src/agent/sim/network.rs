//! A single-thread, manually polled scheduler. No sockets, spawned tasks or clock.
//! QUIC exposes ordered bytes: we reorder polling/delivery between directions,
//! never bytes within a stream. Not polling a direction models delay/backpressure.
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

pub fn link() -> (DuplexStream, DuplexStream, DuplexStream, DuplexStream) {
    let (a, a_wire) = tokio::io::duplex(127);
    let (b, b_wire) = tokio::io::duplex(127);
    (a, b, a_wire, b_wire)
}

async fn relay(
    mut from: impl tokio::io::AsyncRead + Unpin,
    mut to: impl tokio::io::AsyncWrite + Unpin,
    wire: &mut Vec<u8>,
    chunk: usize,
) {
    let mut buf = [0; 113];
    loop {
        let Ok(n) = from.read(&mut buf[..chunk]).await else {
            return;
        };
        if n == 0 {
            let _ = to.shutdown().await;
            return;
        }
        wire.extend_from_slice(&buf[..n]);
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
        // One scheduler turn per chunk even when both buffers are ready.
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }
}

/// Returns both outcomes, or None when the scheduler severs the connection.
/// Wire captures count received bytes even if the handler rejects the batch.
pub fn drive<A, B>(
    a: impl Future<Output = A>,
    b: impl Future<Output = B>,
    a_wire: DuplexStream,
    b_wire: DuplexStream,
    seed: u64,
    cut: Option<usize>,
    mut cancelled: impl FnMut(usize) -> bool,
) -> (Option<(A, B)>, [Vec<u8>; 2]) {
    let mut rng = Rng(seed);
    let mut ab = Vec::new();
    let mut ba = Vec::new();
    let result = {
        let (ar, aw) = tokio::io::split(a_wire);
        let (br, bw) = tokio::io::split(b_wire);
        let mut a = std::pin::pin!(a);
        let mut b = std::pin::pin!(b);
        let mut ab_pump = std::pin::pin!(relay(ar, bw, &mut ab, 1 + (rng.next() % 113) as usize));
        let mut ba_pump = std::pin::pin!(relay(br, aw, &mut ba, 1 + (rng.next() % 113) as usize));
        let mut a_done = None;
        let mut b_done = None;
        let mut ab_done = false;
        let mut ba_done = false;
        let mut cx = Context::from_waker(Waker::noop());
        for tick in 0..100_000 {
            if cut == Some(tick) || cancelled(tick) {
                break;
            }
            match rng.next() % 4 {
                0 if a_done.is_none() => {
                    if let Poll::Ready(value) = a.as_mut().poll(&mut cx) {
                        a_done = Some(value);
                    }
                }
                1 if b_done.is_none() => {
                    if let Poll::Ready(value) = b.as_mut().poll(&mut cx) {
                        b_done = Some(value);
                    }
                }
                2 if !ab_done => ab_done = ab_pump.as_mut().poll(&mut cx).is_ready(),
                3 if !ba_done => ba_done = ba_pump.as_mut().poll(&mut cx).is_ready(),
                _ => {}
            }
            if a_done.is_some() && b_done.is_some() {
                break;
            }
        }
        a_done.zip(b_done)
    };
    (result, [ab, ba])
}
