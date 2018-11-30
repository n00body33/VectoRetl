extern crate futures;
extern crate rand;
extern crate router;
extern crate stream_cancel;
extern crate tokio;

use futures::{Future, Sink, Stream};
use router::{sinks, sources};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use stream_cancel::Tripwire;
use tokio::codec::{BytesCodec, FramedRead, FramedWrite, LinesCodec};
use tokio::net::{TcpListener, TcpStream};

static NEXT_PORT: AtomicUsize = AtomicUsize::new(1234);
fn next_addr() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};

    let port = NEXT_PORT.fetch_add(1, Ordering::AcqRel) as u16;
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[test]
fn test_pipe() {
    let (trigger, tripwire) = Tripwire::new();

    let num_lines: usize = 10000;

    let in_addr = next_addr();
    let out_addr = next_addr();

    let splunk_in = sources::splunk::raw_tcp(in_addr, tripwire);
    let splunk_out = sinks::splunk::raw_tcp(out_addr)
        .map(|sink| sink.sink_map_err(|e| panic!("tcp sink error: {:?}", e)))
        .map_err(|e| panic!("error creating tcp sink: {:?}", e));
    let server = splunk_out.and_then(|sink| splunk_in.forward(sink).map(|_| ()));

    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let output_lines = receive_lines(&out_addr, &rt.executor());

    rt.spawn(server);
    // Wait for server to accept traffic
    while let Err(_) = std::net::TcpStream::connect(in_addr) {}

    let input_lines = random_lines().take(num_lines).collect::<Vec<_>>();
    let send = send_lines(in_addr, input_lines.clone().into_iter());
    rt.block_on(send).unwrap();

    // Shut down server
    drop(trigger);

    rt.shutdown_on_idle().wait().unwrap();
    let output_lines = output_lines.wait().unwrap();
    assert_eq!(num_lines, output_lines.len());
    assert_eq!(input_lines, output_lines);
}

fn random_lines() -> impl Iterator<Item = String> {
    use rand::distributions::Alphanumeric;
    use rand::{rngs::SmallRng, thread_rng, Rng, SeedableRng};

    let mut rng = SmallRng::from_rng(thread_rng()).unwrap();

    std::iter::repeat(()).map(move |_| rng.sample_iter(&Alphanumeric).take(100).collect::<String>())
}

fn send_lines(
    addr: SocketAddr,
    lines: impl Iterator<Item = String>,
) -> impl Future<Item = (), Error = ()> {
    let lines = futures::stream::iter_ok::<_, ()>(lines);

    TcpStream::connect(&addr)
        .map_err(|e| panic!("{:}", e))
        .and_then(|socket| {
            let out =
                FramedWrite::new(socket, LinesCodec::new()).sink_map_err(|e| panic!("{:?}", e));

            lines
                .forward(out)
                .map(|(_source, sink)| sink)
                .and_then(|sink| {
                    // This waits for FIN from the server so we don't start shutting it down before it's fully received the test data
                    let socket = sink.into_inner().into_inner();
                    socket.shutdown(std::net::Shutdown::Write).unwrap();
                    FramedRead::new(socket, BytesCodec::new())
                        .for_each(|_| Ok(()))
                        .map_err(|e| panic!("{:}", e))
                })
        })
}

fn receive_lines(
    addr: &SocketAddr,
    executor: &tokio::runtime::TaskExecutor,
) -> impl Future<Item = Vec<String>, Error = ()> {
    let listener = TcpListener::bind(addr).unwrap();

    let lines = listener
        .incoming()
        .take(1)
        .map(|socket| FramedRead::new(socket, LinesCodec::new()))
        .flatten()
        .map_err(|e| panic!("{:?}", e))
        .collect();

    futures::sync::oneshot::spawn(lines, executor)
}
