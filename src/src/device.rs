use crate::crypto::{identity::NodeCredentials, X25519KeyExchange};
use crate::discovery::DiscoveryResponder;
use crate::handshake::{HandshakeContext, HandshakeError, HandshakeTransport};
use crate::messages::{CapabilitySet, DeviceIdentity};
use crate::session::{AlnpSession, Ed25519Authenticator};

/// Minimal device-side server skeleton that wires discovery + handshake together.
pub struct DeviceServer {
    pub identity: DeviceIdentity,
    pub mac_address: String,
    pub capabilities: CapabilitySet,
    pub credentials: NodeCredentials,
}

impl DeviceServer {
    /// Build a discovery responder that signs replies with the device credentials.
    pub fn discovery_responder(&self) -> DiscoveryResponder {
        DiscoveryResponder {
            identity: self.identity.clone(),
            mac_address: self.mac_address.clone(),
            capabilities: self.capabilities.clone(),
            signer: self.credentials.signing.clone(),
        }
    }

    /// Accept an inbound session using the provided transport.
    pub async fn accept<T: HandshakeTransport + Send>(
        &self,
        transport: &mut T,
    ) -> Result<AlnpSession, HandshakeError> {
        let authenticator = Ed25519Authenticator::new(self.credentials.clone());
        let key_exchange = X25519KeyExchange::new();
        AlnpSession::accept(
            self.identity.clone(),
            self.capabilities.clone(),
            authenticator,
            key_exchange,
            HandshakeContext::default(),
            transport,
        )
        .await
    }
}
