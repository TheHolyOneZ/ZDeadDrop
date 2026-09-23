use zdd_seal::{render, SealOptions, SealState};

const CAPSULES: [&str; 4] = ["for-alex", "cold-wallet", "letters", "server-credentials"];

const STATES: [SealState; 6] = [
    SealState::Sealed,
    SealState::Stirring,
    SealState::Breaking,
    SealState::Broken,
    SealState::Held,
    SealState::Frozen,
];

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: dev_fixtures <out-dir>");
    std::fs::create_dir_all(&out).expect("create output directory");

    let mut written = 0usize;

    for name in CAPSULES {
        let seed = *blake3::hash(name.as_bytes()).as_bytes();
        for state in STATES {
            let svg = render(
                &seed,
                &SealOptions {
                    state,
                    reduced_motion: true,
                    ..Default::default()
                },
            );
            std::fs::write(format!("{out}/{name}-{}.svg", state.label()), svg).unwrap();
            written += 1;
        }
    }

    println!("wrote {written} seals to {out}");
}
