use crate::error::{ClockError, Result};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp(0);

    pub fn since(&self, earlier: Timestamp) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    pub fn plus_secs(&self, secs: u64) -> Timestamp {
        Timestamp(self.0.saturating_add(secs))
    }

    pub fn plus_days(&self, days: u64) -> Timestamp {
        self.plus_secs(days.saturating_mul(SECONDS_PER_DAY))
    }
}

pub const SECONDS_PER_DAY: u64 = 86_400;

pub trait Clock {
    fn now(&self) -> Timestamp;

    fn monotonic_secs(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    fn monotonic_secs(&self) -> u64 {
        use std::sync::OnceLock;
        static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
        ORIGIN
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct VirtualClock {
    wall: std::cell::Cell<u64>,
    monotonic: std::cell::Cell<u64>,
}

impl VirtualClock {
    pub fn starting_at(wall: Timestamp) -> Self {
        Self {
            wall: std::cell::Cell::new(wall.0),
            monotonic: std::cell::Cell::new(0),
        }
    }

    pub fn advance_secs(&self, secs: u64) {
        self.wall.set(self.wall.get().saturating_add(secs));
        self.monotonic
            .set(self.monotonic.get().saturating_add(secs));
    }

    pub fn advance_days(&self, days: u64) {
        self.advance_secs(days.saturating_mul(SECONDS_PER_DAY));
    }

    pub fn tamper_wall_forward(&self, secs: u64) {
        self.wall.set(self.wall.get().saturating_add(secs));
    }

    pub fn tamper_wall_backward(&self, secs: u64) {
        self.wall.set(self.wall.get().saturating_sub(secs));
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.wall.get())
    }

    fn monotonic_secs(&self) -> u64 {
        self.monotonic.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimeAttestation {
    pub asserted: Timestamp,

    pub observed_monotonic: u64,

    pub source: AttestationSource,
}

impl TimeAttestation {
    pub fn obtained(asserted: Timestamp, source: AttestationSource, clock: &impl Clock) -> Self {
        Self {
            asserted,
            observed_monotonic: clock.monotonic_secs(),
            source,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationSource {
    NetworkTime,

    RelaySignedHead,

    TimestampAuthority,
}

pub const ATTESTATION_TOLERANCE_SECS: u64 = 300;

pub const DIVERGENCE_TOLERANCE_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClockWitness {
    pub wall: Timestamp,
    pub monotonic: u64,
}

#[derive(Debug, Clone)]
pub struct ClockIntegrity {
    last: Option<ClockWitness>,
    frozen_reason: Option<ClockError>,
}

impl Default for ClockIntegrity {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockIntegrity {
    pub fn new() -> Self {
        Self {
            last: None,
            frozen_reason: None,
        }
    }

    pub fn resuming_from(witness: ClockWitness) -> Self {
        Self {
            last: Some(witness),
            frozen_reason: None,
        }
    }

    pub fn frozen(&self) -> Option<&ClockError> {
        self.frozen_reason.as_ref()
    }

    pub fn acknowledge(&mut self, clock: &impl Clock) {
        self.frozen_reason = None;
        self.last = Some(ClockWitness {
            wall: clock.now(),
            monotonic: clock.monotonic_secs(),
        });
    }

    pub fn observe(&mut self, clock: &impl Clock) -> Result<Timestamp> {
        if let Some(reason) = &self.frozen_reason {
            return Err(reason.clone().into());
        }

        let wall = clock.now();
        let monotonic = clock.monotonic_secs();

        if let Some(prev) = self.last {
            let restarted = monotonic < prev.monotonic;

            if wall < prev.wall {
                let backwards = prev.wall.0 - wall.0;

                if backwards > ATTESTATION_TOLERANCE_SECS {
                    return Err(self.freeze(ClockError::WentBackwards(backwards)));
                }
            } else if !restarted {
                let wall_delta = wall.since(prev.wall);
                let mono_delta = monotonic - prev.monotonic;

                if wall_delta > mono_delta + DIVERGENCE_TOLERANCE_SECS {
                    return Err(self.freeze(ClockError::ImplausibleJump {
                        jumped: wall_delta,
                        elapsed: mono_delta,
                    }));
                }
            }
        }

        self.last = Some(ClockWitness { wall, monotonic });
        Ok(wall)
    }

    pub fn corroborate(
        &mut self,
        clock: &impl Clock,
        attestation: Option<&TimeAttestation>,
    ) -> Result<Timestamp> {
        let local = self.observe(clock)?;

        let Some(att) = attestation else {
            return Err(self.freeze(ClockError::NoAttestation));
        };

        let mono_now = clock.monotonic_secs();
        if mono_now < att.observed_monotonic {
            return Err(self.freeze(ClockError::StaleAttestation));
        }
        let age = mono_now - att.observed_monotonic;
        let expected = att.asserted.plus_secs(age);

        let drift = expected.0.abs_diff(local.0);
        if drift > ATTESTATION_TOLERANCE_SECS {
            return Err(self.freeze(ClockError::AttestationDisagrees(drift)));
        }

        Ok(local)
    }

    pub fn witness(&self) -> Option<ClockWitness> {
        self.last
    }

    fn freeze(&mut self, reason: ClockError) -> crate::Error {
        self.frozen_reason = Some(reason.clone());
        reason.into()
    }
}

impl Clone for ClockError {
    fn clone(&self) -> Self {
        match self {
            ClockError::WentBackwards(s) => ClockError::WentBackwards(*s),
            ClockError::ImplausibleJump { jumped, elapsed } => ClockError::ImplausibleJump {
                jumped: *jumped,
                elapsed: *elapsed,
            },
            ClockError::NoAttestation => ClockError::NoAttestation,
            ClockError::StaleAttestation => ClockError::StaleAttestation,
            ClockError::AttestationDisagrees(s) => ClockError::AttestationDisagrees(*s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Timestamp = Timestamp(1_800_000_000);

    fn attest(clock: &VirtualClock) -> TimeAttestation {
        TimeAttestation::obtained(clock.now(), AttestationSource::NetworkTime, clock)
    }

    #[test]
    fn honest_time_passes() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();

        for _ in 0..50 {
            integrity.observe(&clock).unwrap();
            clock.advance_days(1);
        }
        assert!(integrity.frozen().is_none());
    }

    #[test]
    fn setting_the_clock_forward_freezes_the_vigil() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        integrity.observe(&clock).unwrap();

        clock.advance_secs(60);
        clock.tamper_wall_forward(365 * SECONDS_PER_DAY);

        let err = integrity.observe(&clock).unwrap_err();
        assert!(matches!(
            err,
            crate::Error::Clock(ClockError::ImplausibleJump { .. })
        ));
        assert!(integrity.frozen().is_some(), "the vigil must stay frozen");
    }

    #[test]
    fn a_freeze_is_sticky() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        integrity.observe(&clock).unwrap();
        clock.tamper_wall_forward(400 * SECONDS_PER_DAY);
        assert!(integrity.observe(&clock).is_err());

        for _ in 0..10 {
            clock.advance_secs(60);
            assert!(
                integrity.observe(&clock).is_err(),
                "freeze must not self-heal"
            );
        }

        integrity.acknowledge(&clock);
        assert!(integrity.frozen().is_none());
        clock.advance_secs(60);
        integrity.observe(&clock).unwrap();
    }

    #[test]
    fn moving_the_clock_backwards_freezes() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        integrity.observe(&clock).unwrap();

        clock.advance_secs(3600);
        clock.tamper_wall_backward(7200);

        assert!(matches!(
            integrity.observe(&clock).unwrap_err(),
            crate::Error::Clock(ClockError::WentBackwards(_))
        ));
    }

    #[test]
    fn small_ntp_corrections_are_tolerated() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        integrity.observe(&clock).unwrap();

        clock.advance_secs(3600);
        clock.tamper_wall_backward(30);
        integrity.observe(&clock).unwrap();
        assert!(integrity.frozen().is_none());
    }

    #[test]
    fn suspend_to_ram_is_tolerated() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        integrity.observe(&clock).unwrap();

        clock.tamper_wall_forward(45 * 60);
        integrity.observe(&clock).unwrap();
        assert!(
            integrity.frozen().is_none(),
            "a closed lid must not freeze the vigil"
        );
    }

    #[test]
    fn corroboration_accepts_an_agreeing_attestation() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        let att = attest(&clock);

        clock.advance_secs(120);
        integrity.corroborate(&clock, Some(&att)).unwrap();
    }

    #[test]
    fn corroboration_catches_tampering_that_survives_a_restart() {
        let clock = VirtualClock::starting_at(T0);
        let att = attest(&clock);

        clock.tamper_wall_forward(365 * SECONDS_PER_DAY);
        let mut integrity = ClockIntegrity::new();

        assert!(ClockIntegrity::new().observe(&clock).is_ok());

        let err = integrity.corroborate(&clock, Some(&att)).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Clock(ClockError::AttestationDisagrees(_))
            ),
            "expected the attestation to contradict the local clock, got {err:?}"
        );
    }

    #[test]
    fn corroboration_requires_an_attestation() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        assert!(matches!(
            integrity.corroborate(&clock, None).unwrap_err(),
            crate::Error::Clock(ClockError::NoAttestation)
        ));
    }

    #[test]
    fn an_aging_attestation_stays_usable() {
        let clock = VirtualClock::starting_at(T0);
        let att = attest(&clock);
        let mut integrity = ClockIntegrity::new();

        clock.advance_secs(3600);
        integrity.corroborate(&clock, Some(&att)).unwrap();

        clock.advance_days(30);
        integrity.corroborate(&clock, Some(&att)).unwrap();
    }

    #[test]
    fn an_attestation_from_before_a_restart_is_refused() {
        let clock = VirtualClock::starting_at(T0);
        clock.advance_days(5);
        let att = attest(&clock);
        assert!(att.observed_monotonic > 0);

        let after_restart = VirtualClock::starting_at(clock.now());
        let mut integrity = ClockIntegrity::new();

        assert!(matches!(
            integrity
                .corroborate(&after_restart, Some(&att))
                .unwrap_err(),
            crate::Error::Clock(ClockError::StaleAttestation)
        ));

        let mut integrity = ClockIntegrity::new();
        let fresh = attest(&after_restart);
        integrity.corroborate(&after_restart, Some(&fresh)).unwrap();
    }

    #[test]
    fn witness_survives_a_restart() {
        let clock = VirtualClock::starting_at(T0);
        let mut integrity = ClockIntegrity::new();
        integrity.observe(&clock).unwrap();
        clock.advance_days(1);
        integrity.observe(&clock).unwrap();

        let witness = integrity.witness().unwrap();
        let json = serde_json::to_string(&witness).unwrap();
        let restored: ClockWitness = serde_json::from_str(&json).unwrap();

        let mut resumed = ClockIntegrity::resuming_from(restored);
        clock.tamper_wall_backward(SECONDS_PER_DAY);
        assert!(
            resumed.observe(&clock).is_err(),
            "a persisted witness must catch tampering across a restart"
        );
    }

    #[test]
    fn timestamp_arithmetic_saturates() {
        assert_eq!(Timestamp(10).since(Timestamp(20)), 0);
        assert_eq!(Timestamp(20).since(Timestamp(10)), 10);
        assert_eq!(Timestamp(u64::MAX).plus_secs(100), Timestamp(u64::MAX));
        assert_eq!(Timestamp(0).plus_days(2), Timestamp(2 * SECONDS_PER_DAY));
    }

    #[test]
    fn the_system_clock_is_sane() {
        let c = SystemClock;

        assert!(c.now().0 > 1_577_836_800, "system clock is before 2020");
        assert!(c.now().0 < 4_102_444_800, "system clock is after 2100");
        let a = c.monotonic_secs();
        assert!(c.monotonic_secs() >= a);
    }
}
