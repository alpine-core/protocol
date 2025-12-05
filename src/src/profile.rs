use sha2::{Digest, Sha256};

/// Declares intent for streaming behavior.
///
/// The value is emitted into the config ID calculation so runtime decisions stay deterministic.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamIntent {
    /// Safe default balancing latency and resilience.
    Auto,
    /// Low-latency intent; favors quick delivery over smoothing.
    Realtime,
    /// Install/resilience intent; favors smoothness over instant updates.
    Install,
}

/// Error produced when stream profile parameters fail validation.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("latency weight must be between 0 and 100 inclusive")]
    LatencyWeightOutOfRange,
    #[error("resilience weight must be between 0 and 100 inclusive")]
    ResilienceWeightOutOfRange,
    #[error("latency and resilience weights cannot both be zero")]
    ZeroTotalWeight,
}

/// High-level description of stream behavior selected by callers.
///
/// The profile is immutable and compiles into a concrete runtime configuration.
#[derive(Debug, Clone)]
pub struct StreamProfile {
    intent: StreamIntent,
    latency_weight: u8,
    resilience_weight: u8,
}

impl StreamProfile {
    /// Returns the safe default profile (Auto).
    pub fn auto() -> Self {
        Self {
            intent: StreamIntent::Auto,
            latency_weight: 50,
            resilience_weight: 50,
        }
    }

    /// Low-latency profile that prioritizes speedy delivery over smoothing.
    pub fn realtime() -> Self {
        Self {
            intent: StreamIntent::Realtime,
            latency_weight: 80,
            resilience_weight: 20,
        }
    }

    /// Install profile that prioritizes smoothness and resilience.
    pub fn install() -> Self {
        Self {
            intent: StreamIntent::Install,
            latency_weight: 25,
            resilience_weight: 75,
        }
    }

    /// Creates a profile with explicit weights; useful for testing or advanced audience.
    pub fn with_weights(intent: StreamIntent, latency_weight: u8, resilience_weight: u8) -> Self {
        Self {
            intent,
            latency_weight,
            resilience_weight,
        }
    }

    /// Normalizes and compiles the profile into a runtime configuration.
    ///
    /// # Guarantees
    /// * Validates each weight and rejects unsafe combinations with explicit errors.
    /// * Produces a deterministic `config_id` derived from the normalized weights and intent.
    pub fn compile(self) -> Result<CompiledStreamProfile, ProfileError> {
        if self.latency_weight > 100 {
            return Err(ProfileError::LatencyWeightOutOfRange);
        }
        if self.resilience_weight > 100 {
            return Err(ProfileError::ResilienceWeightOutOfRange);
        }
        if self.latency_weight == 0 && self.resilience_weight == 0 {
            return Err(ProfileError::ZeroTotalWeight);
        }

        let mut hasher = Sha256::new();
        hasher.update(&[self.latency_weight, self.resilience_weight]);
        hasher.update(&[self.intent as u8]);
        let digest = hasher.finalize();
        let config_id = digest.iter().map(|byte| format!("{:02x}", byte)).collect();

        Ok(CompiledStreamProfile {
            intent: self.intent,
            latency_weight: self.latency_weight,
            resilience_weight: self.resilience_weight,
            config_id,
        })
    }

    /// Returns the declared intent of the profile (Auto/Realtime/Install).
    pub fn intent(&self) -> StreamIntent {
        self.intent
    }
}

/// Deterministic representation of a validated stream profile.
///
/// Users consume this via the SDK to bind runtime behavior and inspect `config_id`.
#[derive(Debug, Clone)]
pub struct CompiledStreamProfile {
    intent: StreamIntent,
    latency_weight: u8,
    resilience_weight: u8,
    config_id: String,
}

impl CompiledStreamProfile {
    /// Returns the stable config ID representing this profile.
    pub fn config_id(&self) -> &str {
        &self.config_id
    }

    /// Latency weight applied by the runtime.
    pub fn latency_weight(&self) -> u8 {
        self.latency_weight
    }

    /// Resilience weight applied by the runtime.
    pub fn resilience_weight(&self) -> u8 {
        self.resilience_weight
    }

    /// Returns the declared intent of the compiled profile.
    pub fn intent(&self) -> StreamIntent {
        self.intent
    }
}

impl Default for StreamProfile {
    fn default() -> Self {
        Self::auto()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_non_zero_weights() {
        let profile = StreamProfile::with_weights(StreamIntent::Auto, 10, 40);
        let compiled = profile.compile().expect("must compile");
        assert_eq!(compiled.latency_weight(), 10);
        assert_eq!(compiled.resilience_weight(), 40);
    }

    #[test]
    fn compile_config_id_deterministic() {
        let a = StreamProfile::auto().compile().unwrap();
        let b = StreamProfile::auto().compile().unwrap();
        assert_eq!(a.config_id(), b.config_id());
    }

    #[test]
    fn default_profile_falls_back_to_auto() {
        let default = StreamProfile::default().compile().unwrap();
        let auto = StreamProfile::auto().compile().unwrap();
        assert_eq!(default.config_id(), auto.config_id());
    }

    #[test]
    fn builtin_profiles_have_distinct_ids() {
        let realtime = StreamProfile::realtime().compile().unwrap();
        let install = StreamProfile::install().compile().unwrap();
        assert_ne!(realtime.config_id(), install.config_id());
    }

    #[test]
    fn reject_zero_weights() {
        let profile = StreamProfile::with_weights(StreamIntent::Auto, 0, 0);
        assert!(matches!(
            profile.compile(),
            Err(ProfileError::ZeroTotalWeight)
        ));
    }

    #[test]
    fn reject_overflow_lat() {
        let profile = StreamProfile::with_weights(StreamIntent::Auto, 200, 0);
        assert!(matches!(
            profile.compile(),
            Err(ProfileError::LatencyWeightOutOfRange)
        ));
    }
}
