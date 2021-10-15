use pin_project::pin_project;
use std::task::{Context, Poll};
use std::{io, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait AfterReadExt {
    fn after_read<F>(self, after_read: F) -> StreamWrapper<Self, F>
    where
        Self: Sized;
}

impl<T: AsyncRead + AsyncWrite> AfterReadExt for T {
    fn after_read<F>(self, after_read: F) -> StreamWrapper<Self, F> {
        StreamWrapper::new(self, after_read)
    }
}

/// This wraps the inner socket and emits `BytesReceived` with the
/// actual number of bytes read before handling framing.
#[pin_project]
pub struct StreamWrapper<T, F> {
    #[pin]
    inner: T,
    after_read: F,
}

impl<T, F> StreamWrapper<T, F> {
    pub const fn new(inner: T, after_read: F) -> Self {
        Self { inner, after_read }
    }

    pub const fn get_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: AsyncRead, F> AsyncRead for StreamWrapper<T, F>
where
    F: Fn(usize),
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            (this.after_read)(buf.filled().len() - before);
        }
        result
    }
}

impl<T: AsyncWrite, F> AsyncWrite for StreamWrapper<T, F> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}
