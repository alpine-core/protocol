use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::Signature;

use crate::crypto::{identity::NodeCredentials, KeyExchange, SessionKeys, X25519KeyExchange};
use crate::handshake::{
    client::ClientHandshake, server::ServerHandshake, ChallengeAuthenticator, HandshakeContext,
    HandshakeError, HandshakeOutcome, HandshakeParticipant, HandshakeTransport,
};
use crate::messages::{CapabilitySet, DeviceIdentity, SessionEstablished};
use crate::profile::CompiledStreamProfile;

pub mod state;
use state::{SessionState, SessionStateError};

impl From<SessionStateError> for HandshakeError {
    fn from(err: SessionStateError) -> Self {
        HandshakeError::Protocol(err.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlnpRole {
    Controller,
    Node,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JitterStrategy {
    HoldLast,
    Drop,
    Lerp,
}

#[derive(Debug, Clone)]
pub struct AlnpSession {
    pub role: AlnpRole,
    state: Arc<Mutex<SessionState>>,
    last_keepalive: Arc<Mutex<Instant>>,
    jitter: Arc<Mutex<JitterStrategy>>,
    streaming_enabled: Arc<Mutex<bool>>,
    timeout: Duration,
    session_established: Arc<Mutex<Option<SessionEstablished>>>,
    session_keys: Arc<Mutex<Option<SessionKeys>>>,
    compiled_profile: Arc<Mutex<Option<CompiledStreamProfile>>>,
    profile_locked: Arc<Mutex<bool>>,
}

impl AlnpSession {
    pub fn new(role: AlnpRole) -> Self {
        Self {
            role,
            state: Arc::new(Mutex::new(SessionState::Init)),
            last_keepalive: Arc::new(Mutex::new(Instant::now())),
            jitter: Arc::new(Mutex::new(JitterStrategy::HoldLast)),
            streaming_enabled: Arc::new(Mutex::new(true)),
            timeout: Duration::from_secs(10),
            session_established: Arc::new(Mutex::new(None)),
            session_keys: Arc::new(Mutex::new(None)),
            compiled_profile: Arc::new(Mutex::new(None)),
            profile_locked: Arc::new(Mutex::new(false)),
        }
    }

    pub fn established(&self) -> Option<SessionEstablished> {
        self.session_established.lock().ok().and_then(|s| s.clone())
    }

    pub fn keys(&self) -> Option<SessionKeys> {
        self.session_keys.lock().ok().and_then(|k| k.clone())
    }

    pub fn state(&self) -> SessionState {
        self.state
            .lock()
            .map(|g| g.clone())
            .unwrap_or(SessionState::Failed("state poisoned".to_string()))
    }

    pub fn ensure_streaming_ready(&self) -> Result<SessionEstablished, HandshakeError> {
        let state = self.state();
        match state {
            SessionState::Ready { .. } | SessionState::Streaming { .. } => {
                self.established().ok_or_else(|| {
                    HandshakeError::Authentication(
                        "session missing even though state is ready".into(),
                    )
                })
            }
            SessionState::Failed(reason) => Err(HandshakeError::Authentication(reason)),
            _ => Err(HandshakeError::Authentication(
                "session not ready; streaming blocked".into(),
            )),
        }
    }

    pub fn update_keepalive(&self) {
        if let Ok(mut k) = self.last_keepalive.lock() {
            *k = Instant::now();
        }
    }

    pub fn check_timeouts(&self) -> Result<(), HandshakeError> {
        let now = Instant::now();
        if let Ok(state) = self.state.lock() {
            if state.check_timeout(self.timeout, now) {
                self.fail("session timeout".into());
                return Err(HandshakeError::Transport("session timeout".into()));
            }
        }
        Ok(())
    }

    /// Sets the stream profile that determines runtime behavior.
    ///
    /// This method locks the profile until streaming begins to enforce immutability.
    pub fn set_stream_profile(&self, profile: CompiledStreamProfile) -> Result<(), HandshakeError> {
        let locked = self
            .profile_locked
            .lock()
            .map_err(|_| HandshakeError::Protocol("profile lock poisoned".into()))?;
        if *locked {
            return Err(HandshakeError::Protocol(
                "stream profile cannot be changed after streaming starts".into(),
            ));
        }
        let mut compiled = self
            .compiled_profile
            .lock()
            .map_err(|_| HandshakeError::Protocol("compiled profile lock poisoned".into()))?;
        *compiled = Some(profile);
        Ok(())
    }

    /// Returns the bound profile's config ID, if set.
    ///
    /// The `config_id` is computed from the normalized profile and never changes.
    #[must_use]
    pub fn profile_config_id(&self) -> Option<String> {
        self.compiled_profile
            .lock()
            .ok()
            .and_then(|guard| guard.clone().map(|profile| profile.config_id().to_string()))
    }

    /// Retrieves the compiled profile, if configured.
    ///
    /// Once streaming starts this returns the same object that controls runtime behavior.
    #[must_use]
    pub fn compiled_profile(&self) -> Option<CompiledStreamProfile> {
        self.compiled_profile
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    #[cfg(test)]
    pub(crate) fn set_locked_profile_for_testing(&self, profile: CompiledStreamProfile) {
        let mut compiled = self.compiled_profile.lock().unwrap();
        *compiled = Some(profile);
        *self.profile_locked.lock().unwrap() = true;
    }

    pub fn set_jitter_strategy(&self, strat: JitterStrategy) {
        if let Ok(mut j) = self.jitter.lock() {
            *j = strat;
        }
    }

    pub fn jitter_strategy(&self) -> JitterStrategy {
        self.jitter
            .lock()
            .map(|j| *j)
            .unwrap_or(JitterStrategy::Drop)
    }

    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = SessionState::Closed;
        }
    }

    pub fn fail(&self, reason: String) {
        if let Ok(mut state) = self.state.lock() {
            *state = SessionState::Failed(reason);
        }
    }

    fn transition(&self, next: SessionState) -> Result<(), SessionStateError> {
        let mut state = self.state.lock().unwrap();
        let current = state.clone();
        *state = current.transition(next)?;
        Ok(())
    }

    pub fn set_streaming_enabled(&self, enabled: bool) {
        if let Ok(mut flag) = self.streaming_enabled.lock() {
            *flag = enabled;
        }
    }

    pub fn mark_streaming(&self) {
        if let Ok(mut state) = self.state.lock() {
            let current = state.clone();
            if let SessionState::Ready { .. } = current {
                let _ = current
                    .transition(SessionState::Streaming {
                        since: Instant::now(),
                    })
                    .map(|next| *state = next);
            }
        }
        if let Ok(mut locked) = self.profile_locked.lock() {
            *locked = true;
        }
    }

    pub fn streaming_enabled(&self) -> bool {
        self.streaming_enabled.lock().map(|f| *f).unwrap_or(false)
    }

    fn apply_outcome(&self, outcome: HandshakeOutcome) {
        if let Ok(mut guard) = self.session_established.lock() {
            *guard = Some(outcome.established);
        }
        if let Ok(mut guard) = self.session_keys.lock() {
            *guard = Some(outcome.keys);
        }
    }

    pub async fn connect<T, A, K>(
        identity: DeviceIdentity,
        capabilities: CapabilitySet,
        authenticator: A,
        key_exchange: K,
        context: HandshakeContext,
        transport: &mut T,
    ) -> Result<Self, HandshakeError>
    where
        T: HandshakeTransport + Send,
        A: ChallengeAuthenticator + Send + Sync,
        K: KeyExchange + Send + Sync,
    {
        let session = Self::new(AlnpRole::Controller);
        session.transition(SessionState::Handshake)?;
        let driver = ClientHandshake {
            identity,
            capabilities,
            authenticator,
            key_exchange,
            context,
        };

        let outcome = driver.run(transport).await?;
        session.transition(SessionState::Authenticated {
            since: Instant::now(),
        })?;
        session.transition(SessionState::Ready {
            since: Instant::now(),
        })?;
        session.apply_outcome(outcome);
        Ok(session)
    }

    pub async fn accept<T, A, K>(
        identity: DeviceIdentity,
        capabilities: CapabilitySet,
        authenticator: A,
        key_exchange: K,
        context: HandshakeContext,
        transport: &mut T,
    ) -> Result<Self, HandshakeError>
    where
        T: HandshakeTransport + Send,
        A: ChallengeAuthenticator + Send + Sync,
        K: KeyExchange + Send + Sync,
    {
        let session = Self::new(AlnpRole::Node);
        session.transition(SessionState::Handshake)?;
        let driver = ServerHandshake {
            identity,
            capabilities,
            authenticator,
            key_exchange,
            context,
        };

        let outcome = driver.run(transport).await?;
        session.transition(SessionState::Authenticated {
            since: Instant::now(),
        })?;
        session.transition(SessionState::Ready {
            since: Instant::now(),
        })?;
        session.apply_outcome(outcome);
        Ok(session)
    }
}

/// Shared-secret authenticator placeholder for signing and verification.
pub struct StaticKeyAuthenticator {
    secret: Vec<u8>,
}

impl StaticKeyAuthenticator {
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }
}

impl Default for StaticKeyAuthenticator {
    fn default() -> Self {
        Self::new(b"default-alnp-secret".to_vec())
    }
}

impl ChallengeAuthenticator for StaticKeyAuthenticator {
    fn sign_challenge(&self, nonce: &[u8]) -> Vec<u8> {
        let mut sig = Vec::with_capacity(self.secret.len() + nonce.len());
        sig.extend_from_slice(&self.secret);
        sig.extend_from_slice(nonce);
        sig
    }

    fn verify_challenge(&self, nonce: &[u8], signature: &[u8]) -> bool {
        signature.ends_with(nonce) && signature.starts_with(&self.secret)
    }
}

/// Ed25519-based authenticator using loaded credentials.
pub struct Ed25519Authenticator {
    creds: NodeCredentials,
}

impl Ed25519Authenticator {
    pub fn new(creds: NodeCredentials) -> Self {
        Self { creds }
    }
}

impl ChallengeAuthenticator for Ed25519Authenticator {
    fn sign_challenge(&self, nonce: &[u8]) -> Vec<u8> {
        self.creds.sign(nonce).to_vec()
    }

    fn verify_challenge(&self, nonce: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = Signature::from_slice(signature) {
            self.creds.verify(nonce, &sig)
        } else {
            false
        }
    }

    fn identity_verifying_key(&self) -> Option<Vec<u8>> {
        Some(self.creds.verifying.to_bytes().to_vec())
    }
}

/// Simplified in-memory transport useful for unit tests and examples.
pub struct LoopbackTransport {
    inbox: Vec<crate::handshake::HandshakeMessage>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self { inbox: Vec::new() }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::StreamProfile;

    #[test]
    fn profile_lock_prevents_profile_swaps() {
        let session = AlnpSession::new(AlnpRole::Controller);
        let compiled = StreamProfile::auto().compile().unwrap();
        session.set_stream_profile(compiled.clone()).unwrap();
        session.mark_streaming();
        assert!(session.set_stream_profile(compiled).is_err());
    }

    #[test]
    fn config_id_matches_profile() {
        let session = AlnpSession::new(AlnpRole::Controller);
        let compiled = StreamProfile::realtime().compile().unwrap();
        session.set_stream_profile(compiled.clone()).unwrap();
        assert_eq!(session.profile_config_id().unwrap(), compiled.config_id());
    }

    #[test]
    fn config_id_stays_locked_after_streaming() {
        let session = AlnpSession::new(AlnpRole::Controller);
        let compiled = StreamProfile::install().compile().unwrap();
        session.set_stream_profile(compiled.clone()).unwrap();
        let before_config = session.profile_config_id().unwrap();
        session.mark_streaming();
        assert_eq!(session.profile_config_id().unwrap(), before_config);
        assert!(session
            .set_stream_profile(StreamProfile::default().compile().unwrap())
            .is_err());
    }
}

#[async_trait]
impl HandshakeTransport for LoopbackTransport {
    async fn send(
        &mut self,
        msg: crate::handshake::HandshakeMessage,
    ) -> Result<(), HandshakeError> {
        self.inbox.push(msg);
        Ok(())
    }

    async fn recv(&mut self) -> Result<crate::handshake::HandshakeMessage, HandshakeError> {
        if self.inbox.is_empty() {
            return Err(HandshakeError::Transport("loopback queue empty".into()));
        }
        Ok(self.inbox.remove(0))
    }
}

/// Helper builder to quickly create a controller-side session with defaults.
pub async fn example_controller_session<T: HandshakeTransport + Send>(
    identity: DeviceIdentity,
    transport: &mut T,
) -> Result<AlnpSession, HandshakeError> {
    AlnpSession::connect(
        identity,
        CapabilitySet::default(),
        StaticKeyAuthenticator::default(),
        X25519KeyExchange::new(),
        HandshakeContext::default(),
        transport,
    )
    .await
}

/// Helper builder to quickly create a node-side session with defaults.
pub async fn example_node_session<T: HandshakeTransport + Send>(
    identity: DeviceIdentity,
    transport: &mut T,
) -> Result<AlnpSession, HandshakeError> {
    AlnpSession::accept(
        identity,
        CapabilitySet::default(),
        StaticKeyAuthenticator::default(),
        X25519KeyExchange::new(),
        HandshakeContext::default(),
        transport,
    )
    .await
}
