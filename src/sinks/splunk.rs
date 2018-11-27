use std::io;
use std::net::SocketAddr;

use futures::{future, Future, Sink};
use tokio::codec::{FramedWrite, LinesCodec};
use tokio::net::TcpStream;

use Record;

pub fn raw_tcp(
    addr: SocketAddr,
) -> impl Future<Item = impl Sink<SinkItem = Record, SinkError = io::Error>, Error = io::Error> {
    // lazy so that we don't actually try to connect until the future is polled
    future::lazy(move || {
        TcpStream::connect(&addr).map(|socket| {
            FramedWrite::new(socket, LinesCodec::new())
                .with(|record: Record| Ok(record.line))
        })
    })
}
