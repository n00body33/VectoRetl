use std::{io, thread};

use async_stream::stream;
use bytes::Bytes;
use chrono::Utc;
use codecs::{
    decoding::{DeserializerConfig, FramingConfig},
    StreamDecodingError,
};
use futures::{channel::mpsc, executor, SinkExt, StreamExt};
use tokio_util::{codec::FramedRead, io::StreamReader};
use vector_core::ByteSizeOf;

use crate::{
    codecs::DecodingConfig,
    config::log_schema,
    internal_events::{BytesReceived, OldEventsReceived, StreamClosedError},
    shutdown::ShutdownSignal,
    SourceSender,
};

pub trait FileDescriptorConfig {
    fn host_key(&self) -> Option<String>;
    fn framing(&self) -> Option<FramingConfig>;
    fn decoding(&self) -> DeserializerConfig;
}

pub fn file_descriptor_source<R, C>(
    mut reader: R,
    config: C,
    shutdown: ShutdownSignal,
    mut out: SourceSender,
    name: &'static str,
) -> crate::Result<crate::sources::Source>
where
    R: Send + io::BufRead + 'static,
    C: FileDescriptorConfig,
{
    let host_key = config
        .host_key()
        .unwrap_or_else(|| log_schema().host_key().to_string());
    let hostname = crate::get_hostname().ok();

    let decoding = config.decoding();
    let framing = config
        .framing()
        .unwrap_or_else(|| decoding.default_stream_framing());
    let decoder = DecodingConfig::new(framing, decoding).build();

    let (mut sender, receiver) = mpsc::channel(1024);

    // Spawn background thread with blocking I/O to process fd.
    //
    // This is recommended by Tokio, as otherwise the process will not shut down
    // until another newline is entered. See
    // https://github.com/tokio-rs/tokio/blob/a73428252b08bf1436f12e76287acbc4600ca0e5/tokio/src/io/stdin.rs#L33-L42
    thread::spawn(move || {
        info!("Capturing fd.");

        loop {
            let (buffer, len) = match reader.fill_buf() {
                Ok(buffer) if buffer.is_empty() => break, // EOF.
                Ok(buffer) => (Ok(Bytes::copy_from_slice(buffer)), buffer.len()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => (Err(error), 0),
            };

            reader.consume(len);

            if executor::block_on(sender.send(buffer)).is_err() {
                // Receiver has closed so we should shutdown.
                break;
            }
        }
    });

    Ok(Box::pin(async move {
        let stream = StreamReader::new(receiver);
        let mut stream = FramedRead::new(stream, decoder).take_until(shutdown);
        let mut stream = stream! {
            while let Some(result) = stream.next().await {
                match result {
                    Ok((events, byte_size)) => {
                        emit!(BytesReceived { byte_size, protocol: "none" });

                        emit!(OldEventsReceived {
                            byte_size: events.size_of(),
                            count: events.len()
                        });

                        let now = Utc::now();

                        for mut event in events {
                            let log = event.as_mut_log();

                            log.try_insert(log_schema().source_type_key(), Bytes::from(name));
                            log.try_insert(log_schema().timestamp_key(), now);

                            if let Some(hostname) = &hostname {
                                log.try_insert(host_key.as_str(), hostname.clone());
                            }

                            yield event;
                        }
                    }
                    Err(error) => {
                        println!("Got an error: {:?}", error);
                        // Error is logged by `crate::codecs::Decoder`, no
                        // further handling is needed here.
                        if !error.can_continue() {
                            break;
                        }
                    }
                }
            }
        }
        .boxed();

        match out.send_event_stream(&mut stream).await {
            Ok(()) => {
                info!("Finished sending.");
                Ok(())
            }
            Err(error) => {
                let (count, _) = stream.size_hint();
                emit!(StreamClosedError { error, count });
                Err(())
            }
        }
    }))
}
