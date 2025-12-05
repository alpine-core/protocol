use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time;

use super::{HandshakeMessage, HandshakeTransport};
use crate::messages::{Keepalive, MessageType};

/// Spawns a keepalive task that periodically pushes Keepalive frames on the control channel.
pub async fn spawn_keepalive<T>(transport: Arc<Mutex<T>>, interval: Duration, session_id: String)
where
    T: HandshakeTransport + Send + 'static,
{
    tokio::spawn(async move {
        let session_id_clone = session_id.clone();
        let payload = HandshakeMessage::Keepalive(Keepalive {
            message_type: MessageType::Keepalive,
            session_id: session_id_clone,
            tick_ms: interval.as_millis() as u64,
        });
        loop {
            time::sleep(interval).await;
            let mut guard = transport.lock().await;
            if let Err(_e) = guard.send(payload.clone()).await {
                // Best-effort; log or trace hook could be added here.
            }
        }
    });
}
