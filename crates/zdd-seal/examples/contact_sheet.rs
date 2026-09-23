use zdd_seal::{render, SealOptions, SealState};

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| std::env::temp_dir().join("seals").display().to_string());
    std::fs::create_dir_all(&out).expect("create output directory");

    for i in 0..24u8 {
        let seed = *blake3::hash(format!("capsule-{i}").as_bytes()).as_bytes();
        let svg = render(&seed, &SealOptions::default());
        std::fs::write(format!("{out}/grid-{i:02}.svg"), svg).unwrap();
    }

    let seed = *blake3::hash(b"for-alex").as_bytes();
    for state in [
        SealState::Sealed,
        SealState::Stirring,
        SealState::Breaking,
        SealState::Broken,
        SealState::Held,
        SealState::Frozen,
    ] {
        let svg = render(
            &seed,
            &SealOptions {
                state,
                reduced_motion: true,
                ..Default::default()
            },
        );
        std::fs::write(format!("{out}/state-{}.svg", state.label()), svg).unwrap();
    }

    for i in 0..8u8 {
        let seed = *blake3::hash(format!("capsule-{i}").as_bytes()).as_bytes();
        let svg = render(&seed, &SealOptions::tray(SealState::Sealed));
        std::fs::write(format!("{out}/tray-{i}.svg"), svg).unwrap();
    }

    println!("{out}");
}
