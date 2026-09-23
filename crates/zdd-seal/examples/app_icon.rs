use zdd_seal::{render, SealOptions, SealState};

fn main() {
    let out = std::env::args().nth(1).expect("usage: app_icon <out.svg>");

    let seed: [u8; 32] = blake3::hash(b"zdeaddrop-icon").into();

    for (suffix, compact) in [("", false), (".tray", true)] {
        let svg = render(
            &seed,
            &SealOptions {
                size: 1024,
                state: SealState::Sealed,
                simplified: true,
                reduced_motion: true,
                compact: Some(compact),
                title: Some("ZDeadDrop".into()),
            },
        );
        let path = out.replace(".svg", &format!("{suffix}.svg"));
        std::fs::write(&path, svg).expect("write icon");
        println!("{path}");
    }
}
