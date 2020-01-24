use crate::event::Event;
use bytes::Buf;
use futures::{sync::mpsc, Future, Sink};
use serde::Serialize;
use std::error::Error;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use stream_cancel::Tripwire;
use warp::filters::BoxedFilter;
use warp::http::{HeaderMap, StatusCode};
use warp::{Filter, Rejection};

#[derive(Serialize, Debug)]
pub struct ErrorMessage {
    code: u16,
    message: String,
}
impl ErrorMessage {
    pub fn new(code: StatusCode, message: String) -> Self {
        ErrorMessage {
            code: code.as_u16(),
            message,
        }
    }
}
impl Error for ErrorMessage {}
impl Display for ErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

fn string_to_static_str(s: String) -> &'static str {
    //necessary because warp 0.1.18 needs a &'static str for the path
    Box::leak(s.into_boxed_str())
}

pub trait HttpSource: Clone + Send + Sync + 'static {
    fn build_event(
        &self,
        body: impl Buf,
        header_map: HeaderMap,
    ) -> Result<Vec<Event>, ErrorMessage>;

    fn run(
        self,
        address: SocketAddr,
        path: String,
        out: mpsc::Sender<Event>,
    ) -> crate::Result<crate::sources::Source> {
        let (trigger, tripwire) = Tripwire::new();
        let trigger = Arc::new(Mutex::new(Some(trigger)));

        let mut filter: BoxedFilter<()> = warp::post2().boxed();
        if path.len() != 0 && path != "/" {
            for s in string_to_static_str(path).split("/") {
                filter = filter.and(warp::path(s)).boxed();
            }
        }
        let svc = filter
            .and(warp::path::end())
            .boxed()
            .and(warp::header::headers_cloned())
            .and(warp::body::concat())
            .and_then(move |headers: HeaderMap, body| {
                let out = out.clone();
                let trigger = trigger.clone();
                info!("Handling http request: {:?}", headers);

                futures::future::result(
                    self.build_event(body, headers)
                        .map_err(warp::reject::custom),
                )
                .and_then(|events| {
                    out.send_all(futures::stream::iter_ok(events)).map_err(
                        move |_: mpsc::SendError<Event>| {
                            error!("Failed to forward events, downstream is closed");
                            // shut down the http server if someone hasn't already
                            trigger.try_lock().ok().take().map(drop);
                            warp::reject::custom("shutting down")
                        },
                    )
                })
                .map(|_| warp::reply())
            });

        let ping = warp::get2().and(warp::path("ping")).map(|| "pong");
        let routes = svc.or(ping).recover(|r: Rejection| {
            let err = {
                if let Some(e_msg) = r.find_cause::<ErrorMessage>() {
                    let json = warp::reply::json(e_msg);
                    Ok(warp::reply::with_status(
                        json,
                        StatusCode::from_u16(e_msg.code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    ))
                } else {
                    //other internal error - will return 500 internal server error
                    Err(r)
                }
            };
            futures::future::result(err)
        });

        info!(message = "building http server", addr = %address);
        let (_, server) = warp::serve(routes).bind_with_graceful_shutdown(address, tripwire);
        Ok(Box::new(server))
    }
}
