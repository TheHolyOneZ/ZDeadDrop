use zdd_core::kdf::{self, label};
use zdd_core::secret::Key32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub seq: i64,
    pub at: u64,
    pub kind: EventKind,

    pub payload: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    VaultCreated,
    VaultUnlocked,
    UnlockPathAdded,
    UnlockPathRemoved,
    CapsuleCreated,
    CapsuleUpdated,
    CapsuleDeleted,
    CheckIn,
    HoldPlaced,
    GateRotated,
    RehearsalRun,
    Released,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::VaultCreated => "vault_created",
            EventKind::VaultUnlocked => "vault_unlocked",
            EventKind::UnlockPathAdded => "unlock_path_added",
            EventKind::UnlockPathRemoved => "unlock_path_removed",
            EventKind::CapsuleCreated => "capsule_created",
            EventKind::CapsuleUpdated => "capsule_updated",
            EventKind::CapsuleDeleted => "capsule_deleted",
            EventKind::CheckIn => "check_in",
            EventKind::HoldPlaced => "hold_placed",
            EventKind::GateRotated => "gate_rotated",
            EventKind::RehearsalRun => "rehearsal_run",
            EventKind::Released => "released",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "vault_created" => EventKind::VaultCreated,
            "vault_unlocked" => EventKind::VaultUnlocked,
            "unlock_path_added" => EventKind::UnlockPathAdded,
            "unlock_path_removed" => EventKind::UnlockPathRemoved,
            "capsule_created" => EventKind::CapsuleCreated,
            "capsule_updated" => EventKind::CapsuleUpdated,
            "capsule_deleted" => EventKind::CapsuleDeleted,
            "check_in" => EventKind::CheckIn,
            "hold_placed" => EventKind::HoldPlaced,
            "gate_rotated" => EventKind::GateRotated,
            "rehearsal_run" => EventKind::RehearsalRun,
            "released" => EventKind::Released,
            _ => return None,
        })
    }
}

pub fn genesis() -> [u8; 32] {
    *blake3::hash(b"zdd/v1/event-chain/genesis").as_bytes()
}

pub fn link_hash(prev: &[u8; 32], seq: i64, at: u64, kind: EventKind, payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"zdd/v1/event-chain/link");
    h.update(prev);
    h.update(&seq.to_be_bytes());
    h.update(&at.to_be_bytes());

    let kind_bytes = kind.as_str().as_bytes();
    h.update(&(kind_bytes.len() as u32).to_be_bytes());
    h.update(kind_bytes);
    h.update(&(payload.len() as u64).to_be_bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

pub fn head_mac(root: &Key32, seq: i64, head: &[u8; 32]) -> [u8; 32] {
    let key = kdf::derive_subkey(root, label::STORE_LOG_CHAIN);
    let mut h = blake3::Hasher::new_keyed(key.expose());
    h.update(b"zdd/v1/event-chain/head");
    h.update(&seq.to_be_bytes());
    h.update(head);
    *h.finalize().as_bytes()
}

pub fn verify(events: &[Event]) -> crate::Result<[u8; 32]> {
    let mut prev = genesis();

    for (expected_seq, event) in (1i64..).zip(events) {
        if event.seq != expected_seq {
            return Err(crate::StoreError::ChainBroken { seq: expected_seq });
        }
        if event.prev_hash != prev {
            return Err(crate::StoreError::ChainBroken { seq: event.seq });
        }
        let computed = link_hash(&prev, event.seq, event.at, event.kind, &event.payload);

        if computed != event.hash {
            return Err(crate::StoreError::ChainBroken { seq: event.seq });
        }
        prev = event.hash;
    }

    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: i64) -> Vec<Event> {
        let mut prev = genesis();
        (1..=n)
            .map(|seq| {
                let payload = format!("event {seq}").into_bytes();
                let at = 1_800_000_000 + seq as u64 * 60;
                let hash = link_hash(&prev, seq, at, EventKind::CheckIn, &payload);
                let e = Event {
                    seq,
                    at,
                    kind: EventKind::CheckIn,
                    payload,
                    prev_hash: prev,
                    hash,
                };
                prev = hash;
                e
            })
            .collect()
    }

    #[test]
    fn an_honest_chain_verifies() {
        let events = chain(20);
        let head = verify(&events).unwrap();
        assert_eq!(head, events.last().unwrap().hash);
    }

    #[test]
    fn an_empty_chain_is_genesis() {
        assert_eq!(verify(&[]).unwrap(), genesis());
    }

    #[test]
    fn removing_an_event_breaks_the_chain() {
        let mut events = chain(10);
        events.remove(4);
        let err = verify(&events).unwrap_err();
        assert!(
            matches!(err, crate::StoreError::ChainBroken { seq: 5 }),
            "got {err:?}"
        );
        assert!(err.is_tampering());
    }

    #[test]
    fn altering_a_payload_breaks_the_chain() {
        let mut events = chain(10);
        events[3].payload = b"something else".to_vec();
        assert!(matches!(
            verify(&events),
            Err(crate::StoreError::ChainBroken { seq: 4 })
        ));
    }

    #[test]
    fn altering_a_timestamp_breaks_the_chain() {
        let mut events = chain(10);
        events[6].at += 1;
        assert!(matches!(
            verify(&events),
            Err(crate::StoreError::ChainBroken { seq: 7 })
        ));
    }

    #[test]
    fn altering_a_kind_breaks_the_chain() {
        let mut events = chain(10);
        events[2].kind = EventKind::Released;
        assert!(matches!(
            verify(&events),
            Err(crate::StoreError::ChainBroken { seq: 3 })
        ));
    }

    #[test]
    fn reordering_events_breaks_the_chain() {
        let mut events = chain(10);
        events.swap(3, 6);
        assert!(verify(&events).is_err());
    }

    #[test]
    fn truncating_the_chain_is_internally_consistent() {
        let events = chain(10);
        assert!(verify(&events[..5]).is_ok());
    }

    #[test]
    fn the_head_mac_catches_truncation() {
        let root = Key32::random();
        let events = chain(10);

        let full_head = verify(&events).unwrap();
        let full_mac = head_mac(&root, 10, &full_head);

        let short_head = verify(&events[..5]).unwrap();
        let short_mac = head_mac(&root, 5, &short_head);

        assert_ne!(full_mac, short_mac);

        assert_ne!(head_mac(&Key32::random(), 5, &short_head), short_mac);
    }

    #[test]
    fn the_head_mac_binds_the_sequence_number() {
        let root = Key32::random();
        let head = [7u8; 32];
        assert_ne!(head_mac(&root, 5, &head), head_mac(&root, 6, &head));
    }

    #[test]
    fn link_hashes_are_unambiguous() {
        let prev = genesis();

        let a = link_hash(&prev, 1, 0, EventKind::CheckIn, b"x");
        let b = link_hash(&prev, 1, 0, EventKind::CheckIn, b"xx");
        assert_ne!(a, b);
        assert_ne!(
            link_hash(&prev, 1, 0, EventKind::CheckIn, b""),
            link_hash(&prev, 1, 0, EventKind::Released, b"")
        );
    }

    #[test]
    fn a_wrong_starting_sequence_is_caught() {
        let mut events = chain(3);
        events[0].seq = 2;
        assert!(verify(&events).is_err());
    }

    #[test]
    fn event_kinds_round_trip() {
        for kind in [
            EventKind::VaultCreated,
            EventKind::VaultUnlocked,
            EventKind::UnlockPathAdded,
            EventKind::UnlockPathRemoved,
            EventKind::CapsuleCreated,
            EventKind::CapsuleUpdated,
            EventKind::CapsuleDeleted,
            EventKind::CheckIn,
            EventKind::HoldPlaced,
            EventKind::GateRotated,
            EventKind::RehearsalRun,
            EventKind::Released,
        ] {
            assert_eq!(EventKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(EventKind::parse("not_a_kind"), None);
    }
}
