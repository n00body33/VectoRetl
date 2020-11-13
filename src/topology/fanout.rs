use crate::Event;
use futures::compat::Future01CompatExt;
use futures01::{future, sync::mpsc, Async, AsyncSink, Poll, Sink, StartSend, Stream};

type RouterSink = Box<dyn Sink<SinkItem = Event, SinkError = ()> + 'static + Send>;

pub struct Fanout {
    sinks: Vec<(String, RouterSink)>,
    i: usize,
    control_channel: mpsc::UnboundedReceiver<ControlMessage>,
}

pub enum ControlMessage {
    Add(String, RouterSink),
    Remove(String),
    Replace(String, RouterSink),
}

pub type ControlChannel = mpsc::UnboundedSender<ControlMessage>;

impl Fanout {
    pub fn new() -> (Self, ControlChannel) {
        let (control_tx, control_rx) = mpsc::unbounded();

        let fanout = Self {
            sinks: vec![],
            i: 0,
            control_channel: control_rx,
        };

        (fanout, control_tx)
    }

    pub fn add(&mut self, name: String, sink: RouterSink) {
        assert!(
            !self.sinks.iter().any(|(n, _)| n == &name),
            "Duplicate output name in fanout"
        );

        self.sinks.push((name, sink));
    }

    fn remove(&mut self, name: &str) {
        let i = self.sinks.iter().position(|(n, _)| n == name);
        let i = i.expect("Didn't find output in fanout");

        let (_name, mut removed) = self.sinks.remove(i);

        tokio::spawn(future::poll_fn(move || removed.close()).compat());

        if self.i > i {
            self.i -= 1;
        }
    }

    fn replace(&mut self, name: String, sink: RouterSink) {
        if let Some((_, existing)) = self.sinks.iter_mut().find(|(n, _)| n == &name) {
            *existing = sink
        } else {
            panic!("Tried to replace a sink that's not already present");
        }
    }

    pub fn process_control_messages(&mut self) {
        while let Ok(Async::Ready(Some(message))) = self.control_channel.poll() {
            match message {
                ControlMessage::Add(name, sink) => self.add(name, sink),
                ControlMessage::Remove(name) => self.remove(&name),
                ControlMessage::Replace(name, sink) => self.replace(name, sink),
            }
        }
    }

    fn handle_sink_error(&mut self, index: usize) -> Result<(), ()> {
        // If there's only one sink, propagate the error to the source ASAP
        // so it stops reading from its input. If there are multiple sinks,
        // keep pushing to the non-errored ones (while the errored sink
        // triggers a more graceful shutdown).
        if self.sinks.len() == 1 {
            Err(())
        } else {
            self.sinks.remove(index);
            Ok(())
        }
    }

    fn poll_sinks(&mut self, close: bool) -> Poll<(), ()> {
        self.process_control_messages();

        let mut poll_result = Async::Ready(());

        // Cannot remove a sink while iterating over them, so just make
        // note of sink error and handle them later.
        let mut errors = vec![];

        for (i, (_name, sink)) in self.sinks.iter_mut().enumerate() {
            let result = if close {
                sink.close()
            } else {
                sink.poll_complete()
            };

            match result {
                Ok(Async::Ready(())) => {}
                Ok(Async::NotReady) => poll_result = Async::NotReady,
                Err(()) => errors.push(i),
            }
        }

        for i in errors {
            self.handle_sink_error(i)?;
        }

        Ok(poll_result)
    }
}

impl Sink for Fanout {
    type SinkItem = Event;
    type SinkError = ();

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.process_control_messages();

        if self.sinks.is_empty() {
            return Ok(AsyncSink::Ready);
        }

        while self.i < self.sinks.len() - 1 {
            let (_name, sink) = &mut self.sinks[self.i];
            match sink.start_send(item.clone()) {
                Ok(AsyncSink::NotReady(item)) => return Ok(AsyncSink::NotReady(item)),
                Ok(AsyncSink::Ready) => self.i += 1,
                Err(()) => self.handle_sink_error(self.i)?,
            }
        }

        let (_name, sink) = &mut self.sinks[self.i];
        match sink.start_send(item) {
            Ok(AsyncSink::NotReady(item)) => return Ok(AsyncSink::NotReady(item)),
            Ok(AsyncSink::Ready) => self.i += 1,
            Err(()) => self.handle_sink_error(self.i)?,
        }

        self.i = 0;

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.poll_sinks(false)
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.poll_sinks(true)
    }
}

#[cfg(test)]
mod tests {
    use super::{ControlMessage, Fanout};
    use crate::{test_util::collect_ready, Event};
    use futures::compat::Future01CompatExt;
    use futures01::{stream, sync::mpsc, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
    use tokio::time::{delay_for, Duration};

    #[tokio::test]
    async fn fanout_writes_to_all() {
        let (tx_a, rx_a) = mpsc::unbounded();
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::unbounded();
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));

        let mut fanout = Fanout::new().0;

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);

        let recs = make_events(2);
        let fanout = fanout.send_all(stream::iter_ok(recs.clone())).compat();
        let _ = fanout.await.unwrap();

        assert_eq!(collect_ready(rx_a).await.unwrap(), recs);
        assert_eq!(collect_ready(rx_b).await.unwrap(), recs);
    }

    #[tokio::test]
    async fn fanout_notready() {
        let (tx_a, rx_a) = mpsc::channel(1);
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::channel(0);
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));
        let (tx_c, rx_c) = mpsc::channel(1);
        let tx_c = Box::new(tx_c.sink_map_err(|_| unreachable!()));

        let mut fanout = Fanout::new().0;

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);
        fanout.add("c".to_string(), tx_c);

        let recs = make_events(3);
        let send = fanout.send_all(stream::iter_ok(recs.clone()));
        tokio::spawn(send.map(|_| ()).compat());

        delay_for(Duration::from_millis(50)).await;
        // The send_all task will be blocked on sending rec2 to b right now.

        let collect_a = tokio::spawn(rx_a.collect().compat());
        let collect_b = tokio::spawn(rx_b.collect().compat());
        let collect_c = tokio::spawn(rx_c.collect().compat());

        assert_eq!(collect_a.await.unwrap().unwrap(), recs);
        assert_eq!(collect_b.await.unwrap().unwrap(), recs);
        assert_eq!(collect_c.await.unwrap().unwrap(), recs);
    }

    #[tokio::test]
    async fn fanout_grow() {
        let (tx_a, rx_a) = mpsc::unbounded();
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::unbounded();
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));

        let mut fanout = Fanout::new().0;

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);

        let recs = make_events(3);

        let fanout = fanout.send(recs[0].clone()).compat().await.unwrap();
        let mut fanout = fanout.send(recs[1].clone()).compat().await.unwrap();

        let (tx_c, rx_c) = mpsc::unbounded();
        let tx_c = Box::new(tx_c.sink_map_err(|_| unreachable!()));
        fanout.add("c".to_string(), tx_c);

        let _fanout = fanout.send(recs[2].clone()).compat().await.unwrap();

        assert_eq!(collect_ready(rx_a).await.unwrap(), recs);
        assert_eq!(collect_ready(rx_b).await.unwrap(), recs);
        assert_eq!(collect_ready(rx_c).await.unwrap(), &recs[2..]);
    }

    #[tokio::test]
    async fn fanout_shrink() {
        let (tx_a, rx_a) = mpsc::unbounded();
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::unbounded();
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));

        let (mut fanout, fanout_control) = Fanout::new();

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);

        let recs = make_events(3);

        let fanout = fanout.send(recs[0].clone()).compat().await.unwrap();
        let fanout = fanout.send(recs[1].clone()).compat().await.unwrap();

        fanout_control
            .unbounded_send(ControlMessage::Remove("b".to_string()))
            .unwrap();

        use futures::compat::Future01CompatExt;
        let _fanout = fanout.send(recs[2].clone()).compat().await.unwrap();

        assert_eq!(collect_ready(rx_a).await.unwrap(), recs);
        assert_eq!(collect_ready(rx_b).await.unwrap(), &recs[..2]);
    }

    #[tokio::test]
    async fn fanout_shrink_after_notready() {
        let (tx_a, rx_a) = mpsc::channel(1);
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::channel(0);
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));
        let (tx_c, rx_c) = mpsc::channel(1);
        let tx_c = Box::new(tx_c.sink_map_err(|_| unreachable!()));

        let (mut fanout, fanout_control) = Fanout::new();

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);
        fanout.add("c".to_string(), tx_c);

        let recs = make_events(3);
        let send = fanout.send_all(stream::iter_ok(recs.clone()));
        tokio::spawn(send.map(|_| ()).compat());

        delay_for(Duration::from_millis(50)).await;
        // The send_all task will be blocked on sending rec2 to b right now.
        fanout_control
            .unbounded_send(ControlMessage::Remove("c".to_string()))
            .unwrap();

        let collect_a = tokio::spawn(rx_a.collect().compat());
        let collect_b = tokio::spawn(rx_b.collect().compat());
        let collect_c = tokio::spawn(rx_c.collect().compat());

        assert_eq!(collect_a.await.unwrap().unwrap(), recs);
        assert_eq!(collect_b.await.unwrap().unwrap(), recs);
        assert_eq!(collect_c.await.unwrap().unwrap(), &recs[..1]);
    }

    #[tokio::test]
    async fn fanout_shrink_at_notready() {
        let (tx_a, rx_a) = mpsc::channel(1);
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::channel(0);
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));
        let (tx_c, rx_c) = mpsc::channel(1);
        let tx_c = Box::new(tx_c.sink_map_err(|_| unreachable!()));

        let (mut fanout, fanout_control) = Fanout::new();

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);
        fanout.add("c".to_string(), tx_c);

        let recs = make_events(3);
        let send = fanout.send_all(stream::iter_ok(recs.clone()));
        tokio::spawn(send.map(|_| ()).compat());

        delay_for(Duration::from_millis(50)).await;
        // The send_all task will be blocked on sending rec2 to b right now.
        fanout_control
            .unbounded_send(ControlMessage::Remove("b".to_string()))
            .unwrap();

        let collect_a = tokio::spawn(rx_a.collect().compat());
        let collect_b = tokio::spawn(rx_b.collect().compat());
        let collect_c = tokio::spawn(rx_c.collect().compat());

        assert_eq!(collect_a.await.unwrap().unwrap(), recs);
        assert_eq!(collect_b.await.unwrap().unwrap(), &recs[..1]);
        assert_eq!(collect_c.await.unwrap().unwrap(), recs);
    }

    #[tokio::test]
    async fn fanout_shrink_before_notready() {
        let (tx_a, rx_a) = mpsc::channel(1);
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::channel(0);
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));
        let (tx_c, rx_c) = mpsc::channel(1);
        let tx_c = Box::new(tx_c.sink_map_err(|_| unreachable!()));

        let (mut fanout, fanout_control) = Fanout::new();

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);
        fanout.add("c".to_string(), tx_c);

        let recs = make_events(3);
        let send = fanout.send_all(stream::iter_ok(recs.clone()));
        tokio::spawn(send.map(|_| ()).compat());

        delay_for(Duration::from_millis(50)).await;
        // The send_all task will be blocked on sending rec2 to b right now.

        fanout_control
            .unbounded_send(ControlMessage::Remove("a".to_string()))
            .unwrap();

        let collect_a = tokio::spawn(rx_a.collect().compat());
        let collect_b = tokio::spawn(rx_b.collect().compat());
        let collect_c = tokio::spawn(rx_c.collect().compat());

        assert_eq!(collect_a.await.unwrap().unwrap(), &recs[..2]);
        assert_eq!(collect_b.await.unwrap().unwrap(), recs);
        assert_eq!(collect_c.await.unwrap().unwrap(), recs);
    }

    #[tokio::test]
    async fn fanout_no_sinks() {
        let fanout = Fanout::new().0;

        let recs = make_events(2);

        let fanout = fanout.send(recs[0].clone()).compat().await.unwrap();
        let _fanout = fanout.send(recs[1].clone()).compat().await.unwrap();
    }

    #[tokio::test]
    async fn fanout_replace() {
        let (tx_a1, rx_a1) = mpsc::unbounded();
        let tx_a1 = Box::new(tx_a1.sink_map_err(|_| unreachable!()));
        let (tx_b, rx_b) = mpsc::unbounded();
        let tx_b = Box::new(tx_b.sink_map_err(|_| unreachable!()));

        let mut fanout = Fanout::new().0;

        fanout.add("a".to_string(), tx_a1);
        fanout.add("b".to_string(), tx_b);

        let recs = make_events(3);

        let fanout = fanout.send(recs[0].clone()).compat().await.unwrap();
        let mut fanout = fanout.send(recs[1].clone()).compat().await.unwrap();

        let (tx_a2, rx_a2) = mpsc::unbounded();
        let tx_a2 = Box::new(tx_a2.sink_map_err(|_| unreachable!()));
        fanout.replace("a".to_string(), tx_a2);

        let _fanout = fanout.send(recs[2].clone()).compat().await.unwrap();

        assert_eq!(collect_ready(rx_a1).await.unwrap(), &recs[..2]);
        assert_eq!(collect_ready(rx_b).await.unwrap(), recs);
        assert_eq!(collect_ready(rx_a2).await.unwrap(), &recs[2..]);
    }

    #[tokio::test]
    async fn fanout_error_send() {
        fanout_error(ErrorWhen::Send).await
    }

    #[tokio::test]
    async fn fanout_error_poll() {
        fanout_error(ErrorWhen::Poll).await
    }

    async fn fanout_error(when: ErrorWhen) {
        let (tx_a, rx_a) = mpsc::channel(1);
        let tx_a = Box::new(tx_a.sink_map_err(|_| unreachable!()));

        let tx_b = AlwaysErrors { when };
        let tx_b = Box::new(tx_b.sink_map_err(|_| ()));

        let (tx_c, rx_c) = mpsc::channel(1);
        let tx_c = Box::new(tx_c.sink_map_err(|_| unreachable!()));

        let mut fanout = Fanout::new().0;

        fanout.add("a".to_string(), tx_a);
        fanout.add("b".to_string(), tx_b);
        fanout.add("c".to_string(), tx_c);

        let recs = make_events(3);
        let send = fanout.send_all(stream::iter_ok(recs.clone()));
        tokio::spawn(send.map(|_| ()).compat());

        delay_for(Duration::from_millis(50)).await;

        let collect_a = tokio::spawn(rx_a.collect().compat());
        let collect_c = tokio::spawn(rx_c.collect().compat());

        assert_eq!(collect_a.await.unwrap().unwrap(), recs);
        assert_eq!(collect_c.await.unwrap().unwrap(), recs);
    }

    enum ErrorWhen {
        Send,
        Poll,
    }

    struct AlwaysErrors {
        when: ErrorWhen,
    }

    impl Sink for AlwaysErrors {
        type SinkItem = Event;
        type SinkError = crate::Error;

        fn start_send(
            &mut self,
            _item: Self::SinkItem,
        ) -> StartSend<Self::SinkItem, Self::SinkError> {
            match self.when {
                ErrorWhen::Send => Err("Something failed".into()),
                _ => Ok(AsyncSink::Ready),
            }
        }

        fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
            match self.when {
                ErrorWhen::Poll => Err("Something failed".into()),
                _ => Ok(Async::Ready(())),
            }
        }
    }

    fn make_events(count: usize) -> Vec<Event> {
        (0..count)
            .map(|i| Event::from(format!("line {}", i)))
            .collect()
    }
}
