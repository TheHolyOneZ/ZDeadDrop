use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn zdd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdd"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run zdd")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn all(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

struct Scene {
    _dir: tempfile::TempDir,
    root: PathBuf,
    key: PathBuf,
    capsule: PathBuf,
    relay: String,
    trustees: Vec<String>,
    sources: Vec<PathBuf>,
}

impl Scene {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let key = root.join("alex.key");
        let out = zdd(&["keygen", "--out", key.to_str().unwrap()]);
        assert!(out.status.success(), "keygen failed: {}", all(&out));

        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        let sources: Vec<PathBuf> = [
            ("letter.txt", b"the deed is in the safe".to_vec()),
            (
                "archive.bin",
                (0..3_000_000u32).map(|i| (i % 251) as u8).collect(),
            ),
            ("keys.txt", b"ssh-ed25519 AAAA".to_vec()),
        ]
        .into_iter()
        .map(|(name, data)| {
            let p = src.join(name);
            std::fs::write(&p, data).unwrap();
            p
        })
        .collect();

        let capsule = root.join("for-alex.capsule");
        let mut args: Vec<String> = vec![
            "seal".into(),
            "--name".into(),
            "For Alex".into(),
            "--note".into(),
            "Read the letter first.".into(),
            "--to".into(),
            key.display().to_string(),
            "--quorum".into(),
            "3".into(),
            "--trustees".into(),
            "5".into(),
            "--out".into(),
            capsule.display().to_string(),
        ];
        args.extend(sources.iter().map(|p| p.display().to_string()));

        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = zdd(&refs);
        assert!(out.status.success(), "seal failed: {}", all(&out));

        let text = all(&out);
        let relay = field(&text, "Relay share").expect("seal must print a relay share");
        let trustees: Vec<String> = (1..=5)
            .filter_map(|i| field(&text, &format!("Trustee {i}")))
            .collect();
        assert_eq!(trustees.len(), 5, "seal must print every trustee share");

        Self {
            _dir: dir,
            root,
            key,
            capsule,
            relay,
            trustees,
            sources,
        }
    }

    fn claim_args(&self, out: &Path, which: &[usize]) -> Vec<String> {
        let mut args = vec![
            "claim".into(),
            "--key".into(),
            self.key.display().to_string(),
            "--relay-share".into(),
            self.relay.clone(),
        ];
        for &i in which {
            args.push("--trustee-share".into());
            args.push(self.trustees[i].clone());
        }
        args.push("--out".into());
        args.push(out.display().to_string());
        args.push(self.capsule.display().to_string());
        args
    }

    fn claim(&self, out: &Path, which: &[usize]) -> Output {
        let args = self.claim_args(out, which);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        zdd(&refs)
    }
}

fn field(text: &str, label: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim_start().starts_with(label))
        .map(|l| l.trim_start().trim_start_matches(label).trim().to_string())
        .filter(|v| !v.is_empty())
}

#[test]
fn a_recipient_can_claim_with_only_the_binary_and_their_key() {
    let scene = Scene::new();
    let out = scene.root.join("claimed");

    let result = scene.claim(&out, &[0, 1, 3]);
    assert!(result.status.success(), "claim failed: {}", all(&result));

    let text = all(&result);
    assert!(
        text.contains("Opened"),
        "claim did not report success: {text}"
    );
    assert!(
        text.contains("Read the letter first."),
        "the note was not shown"
    );

    for source in &scene.sources {
        let name = source.file_name().unwrap();
        let extracted = out.join(name);
        assert!(extracted.exists(), "{name:?} was not extracted");
        assert_eq!(
            std::fs::read(&extracted).unwrap(),
            std::fs::read(source).unwrap(),
            "{name:?} did not survive the round trip"
        );
    }
}

#[test]
fn any_three_trustees_suffice() {
    let scene = Scene::new();
    for which in [[0, 1, 2], [2, 3, 4], [0, 2, 4], [1, 3, 4]] {
        let out = scene
            .root
            .join(format!("claimed-{}{}{}", which[0], which[1], which[2]));
        let result = scene.claim(&out, &which);
        assert!(
            result.status.success(),
            "shares {which:?} failed: {}",
            all(&result)
        );
    }
}

#[test]
fn a_short_quorum_says_what_is_missing() {
    let scene = Scene::new();
    let result = scene.claim(&scene.root.join("nope"), &[0, 1]);

    assert!(!result.status.success());
    let text = all(&result);
    assert!(
        text.contains("2 of the 3"),
        "the message must name how many more shares are needed: {text}"
    );
    assert!(
        !scene.root.join("nope").exists(),
        "a failed claim must write nothing"
    );
}

#[test]
fn one_trustee_repeated_does_not_satisfy_the_quorum() {
    let scene = Scene::new();
    let result = scene.claim(&scene.root.join("nope"), &[1, 1, 1]);
    assert!(
        !result.status.success(),
        "a repeated share formed a quorum: {}",
        all(&result)
    );
}

#[test]
fn trustees_alone_cannot_open_it() {
    let scene = Scene::new();
    let out = scene.root.join("nope");

    let mut args = vec![
        "claim".to_string(),
        "--key".into(),
        scene.key.display().to_string(),
    ];
    for i in 0..3 {
        args.push("--trustee-share".into());
        args.push(scene.trustees[i].clone());
    }
    args.push("--out".into());
    args.push(out.display().to_string());
    args.push(scene.capsule.display().to_string());

    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = zdd(&refs);
    assert!(
        !result.status.success(),
        "trustees alone opened the capsule: {}",
        all(&result)
    );
    assert!(
        all(&result).contains("relay"),
        "the message should mention the relay's share"
    );
}

#[test]
fn the_wrong_key_is_explained_rather_than_rejected() {
    let scene = Scene::new();
    let stranger = scene.root.join("stranger.key");
    assert!(zdd(&["keygen", "--out", stranger.to_str().unwrap()])
        .status
        .success());

    let mut args = scene.claim_args(&scene.root.join("nope"), &[0, 1, 2]);

    let pos = args.iter().position(|a| a == "--key").unwrap();
    args[pos + 1] = stranger.display().to_string();

    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = zdd(&refs);

    assert!(!result.status.success());
    let text = all(&result);
    assert!(
        text.contains("not left to the key"),
        "unhelpful message: {text}"
    );

    assert!(
        text.matches("-").count() > 4,
        "should print both fingerprints: {text}"
    );
}

#[test]
fn claiming_never_overwrites() {
    let scene = Scene::new();
    let out = scene.root.join("claimed");

    assert!(scene.claim(&out, &[0, 1, 2]).status.success());
    let before = std::fs::read(out.join("letter.txt")).unwrap();

    let second = scene.claim(&out, &[0, 1, 2]);
    assert!(
        !second.status.success(),
        "the second claim overwrote: {}",
        all(&second)
    );
    assert!(all(&second).contains("Nothing has been changed"));
    assert_eq!(std::fs::read(out.join("letter.txt")).unwrap(), before);
}

#[test]
fn inspect_describes_without_extracting() {
    let scene = Scene::new();
    let result = zdd(&[
        "claim",
        "--key",
        scene.key.to_str().unwrap(),
        "--inspect",
        scene.capsule.to_str().unwrap(),
    ]);

    assert!(result.status.success(), "{}", all(&result));
    let text = all(&result);
    assert!(
        text.contains("Seal"),
        "inspect must show the seal to compare"
    );
    assert!(
        text.contains("Picture"),
        "inspect must describe the seal in words too"
    );
    assert!(text.contains("Nothing was extracted"));

    assert!(!text.contains("Opened"));
}

#[test]
fn a_tampered_capsule_is_refused() {
    let scene = Scene::new();

    let mut capsule: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&scene.capsule).unwrap()).unwrap();

    capsule["recipients"][0]["public_key"] =
        serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    std::fs::write(&scene.capsule, capsule.to_string()).unwrap();

    let result = scene.claim(&scene.root.join("nope"), &[0, 1, 2]);
    assert!(
        !result.status.success(),
        "a tampered capsule opened: {}",
        all(&result)
    );
}

#[test]
fn a_file_that_is_not_a_capsule_says_so_plainly() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("holiday.jpg");
    std::fs::write(&junk, b"not a capsule at all").unwrap();
    let key = dir.path().join("k.key");
    assert!(zdd(&["keygen", "--out", key.to_str().unwrap()])
        .status
        .success());

    let result = zdd(&[
        "claim",
        "--key",
        key.to_str().unwrap(),
        "--inspect",
        junk.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(
        all(&result).contains("does not look like a ZDeadDrop capsule"),
        "unhelpful: {}",
        all(&result)
    );
}

#[test]
fn keygen_refuses_to_overwrite_an_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    assert!(zdd(&["keygen", "--out", key.to_str().unwrap()])
        .status
        .success());
    let first = std::fs::read(&key).unwrap();

    let second = zdd(&["keygen", "--out", key.to_str().unwrap()]);
    assert!(!second.status.success(), "keygen overwrote a private key");
    assert_eq!(std::fs::read(&key).unwrap(), first);
}

#[test]
fn help_points_a_recipient_at_claim() {
    let out = zdd(&["--help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("left you"),
        "help must address someone who was left something: {text}"
    );
    assert!(text.contains("zdd claim"));
}
