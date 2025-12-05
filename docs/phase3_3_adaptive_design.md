# Phase 3.3 — Adaptive Streaming (Design Only)

This document captures the **design contract** for Phase 3.3 before any code is written. Each section strictly adheres to the existing Phase 3 guardrails: adaptations respect the Phase 3.1 detection signals, reuse the Phase 3.2 recovery machinery, and never violate temporal correctness. No SDK changes, profile redefinitions, or implementation work happen until this contract is agreed.

## 1. Goals & Non-Goals

### Goals
- Use deterministic network signals (loss ratio, burst gaps, late rates, jitter) to make conservative adjustments that preserve a correct timeline.
- Keep adaptation strictly profile-bound and monotonic so every device exposed to the same packet stream arrives at the same adaptive state.
- Explicitly surface when we change behavior so operators can understand why quality shifted.

### Non-Goals
- No profile swapping or semantic changes to `StreamProfile` (Auto/Realtime/Install remain fixed).
- No speculative heuristics (prediction, smoothing, or machine learning) until a later phase.
- No UI, dashboards, or developer-facing knobs beyond the documented guarantees.
- Adaptation will **never** rewind or reorder packets; time stays monotonic at all times.

## 2. Inputs

### Allowed Signals
- `NetworkConditions::metrics()` (loss_ratio, late_frame_rate, jitter_ms) from Phase 3.1.
- `NetworkConditions::max_loss_gap()` (burst size) and `RecoveryMonitor::active_reason()` from Phase 3.2.

### Sampling Strategy
- Use **fixed-size windows** (e.g., 8 frames) sampled when a streaming client observes a new packet.
- Each window computes moving averages with **hysteresis**:
  * For loss_ratio and late_frame_rate, require two consecutive windows exceeding thresholds before adaptation upsizes.
  * For jitter_ms, only adjust when the delta between successive windows exceeds 15% of the current value (avoids flutter).
- Burst gaps immediately take effect (no hysteresis) but only trigger once per burst and clear only after gap drops below 1 sequence for two windows.
- Always log the metrics that caused an adaptation decision; however, adaptation happens only when every sample in the window is deterministic (based on received packets).

## 3. Allowed Adaptations (Whitelisted)

All adaptations are **additive** and **monotonic** within the session lifetime (no oscillation back to a more aggressive state without explicitly hitting a degraded-safe reset):

1. **Keyframe cadence increase**  
   * Trigger: sustained loss_ratio ≥ 30% OR burst gap ≥ 5 sequences.  
   * Effect: Emit a keyframe every `N` frames where `N` decreases by 1 per adaptation step but never below profile-defined minimum.  
   * Enforcement: The next keyframe is flagged via metadata; the actual timeline isn’t rewound — only a special flag requests devices to treat the next frame as authoritative.

2. **Delta depth reduction**  
   * Trigger: late_frame_rate ≥ 20% + jitter_ms spike > 5 ms.  
   * Effect: Limit encoded deltas to a single dependency (instead of delta-on-delta), reducing bandwidth/carry-over errors.  
   * Enforcement: Track the delta depth state and document via metadata whenever it changes.

3. **Delta disable (keyframes-only fallback)**  
   * Trigger: sustained loss_ratio ≥ 50% **and** burst gap ≥ 8, or RecoveryMonitor is already active for `BurstLoss`.  
   * Effect: Suspend delta encoding entirely until metrics fall below recovery-clear thresholds.  
   * Enforcement: Log the transition, and all subsequent frames are flagged so receivers know they won’t rely on past deltas.

4. **Deadline tightening/relaxing within profile bounds**  
   * Trigger: jitter_ms trend upward for two windows (tighten) or downward (relax).  
   * Effect: Reduce/increase delivery deadlines in microseconds, but never go below the profile floor or above the profile ceiling defined in Phase 2 docs.  
   * Enforcement: Each step adjusts deadlines by a fixed delta (e.g., 10% of profile range).

Anything not listed (e.g., changing priority, reordering frames, changing profiles) is forbidden until another phase explicitly allows it.

## 4. Profile-Bound Constraints

Each `StreamProfile` class defines:
- **Auto**: mid-range deadlines, balanced keyframe cadence. May tolerate up to 40% loss with gradual adaptation but never disables deltas unless recovery demands it.
- **Realtime**: latency-first. Deadlines cannot be relaxed beyond the base value; keyframe cadence can only increase up to a safe minimum (guardrail: ≥1 keyframe every 8 frames). Delta depth may never drop below 1 (i.e., still allow delta-on-delta) unless RecoveryMonitor is active for `BurstLoss`.
- **Install**: resilience-first. Deadlines can be relaxed up to the high bound, and keyframe cadence can shift faster (minimum 1 every 4 frames). Delta disable is permitted earlier since the profile already favors smoothness.

## 5. Degraded-Safe Mode

### Triggers
- Attempting an adaptation that would breach profile bounds (e.g., Realtime deadline < floor, Auto cadence < 1/6).  
- RecoveryMonitor is active and loss_ratio ≥ 60% **and** burst gap ≥ 10 sequences (the network cannot sustain streaming without a known fallback).

### Enforced Behavior
- Record a deterministic `DegradedSafe` state in metadata (reason: `ExceededProfileBounds` or `UnrecoverableBurst`).  
- Force keyframes-only (delta depth = 0) and keep the cadence at the profile minimum.  
- Do not introduce new adaptations while in this mode; only the clear condition can exit it.

### Exit
- Exit once metrics fall below the recovery-clear thresholds **and** `RecoveryMonitor::feed` emits `RecoveryComplete`.  
- Restore the last safe configuration snapshot (deadlines, delta state) before employment of degraded-safe mode so behavior is deterministic.

## 6. Determinism & Oscillation Rules

- Each adaptation step has a **minimum dwell time** (e.g., at least 8 frame arrivals) before another step is considered.  
- All adjustments are **monotonic**: we only move toward more conservative states unless a full recovery/reset (including degraded-safe mode) occurs.  
- The combination of deterministic signals + dwell times ensures “same packets → same adaptive state” for every device.  
- Once we record a metadata flag (e.g., `alpine_adaptation = keyframe_cadence`), replaying the same packet stream reproduces that flag precisely without variation.

## 7. Observability

- Log every adaptation decision with the triggering metrics, recovery reason, and resulting state change (use structured `tracing` events).  
- Annotate each frame when adaptation is active (`alpine_adaptation` and `alpine_recovery` metadata) so receivers can reason posthoc.  
- Record degraded-safe mode transitions with explicit reasons plus metric snapshots so we can explain why the stream dropped to keyframes-only.  
- Keep logs session-scoped (no cross-session aggregation) to preserve determinism; rely on consistent timestamps derived from packet arrival times.
