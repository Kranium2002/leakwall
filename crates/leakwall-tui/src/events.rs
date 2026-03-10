use leakwall_proxy::ProxyEvent;
use tokio::sync::broadcast;

/// Create an event channel for proxy → TUI communication.
pub fn create_event_channel() -> (
    broadcast::Sender<ProxyEvent>,
    broadcast::Receiver<ProxyEvent>,
) {
    broadcast::channel(1024)
}

/// Event stream consumer that can be shared across multiple listeners.
pub struct EventConsumer {
    rx: broadcast::Receiver<ProxyEvent>,
}

impl EventConsumer {
    pub fn new(rx: broadcast::Receiver<ProxyEvent>) -> Self {
        Self { rx }
    }

    /// Receive the next event, blocking until available.
    pub async fn next(&mut self) -> Option<ProxyEvent> {
        self.rx.recv().await.ok()
    }
}
