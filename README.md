<div align="center">

# ZDeadDrop

**A local-first digital dead-man's switch and encrypted legacy vault.**

*If you go silent, the right things reach the right people — and nobody else, ever.*

![ZDeadDrop in its two themes, ink and parchment](docs/screenshots/hero.png)

</div>

---

## What it is for

Most people have something exactly one person should receive if they die or
disappear, and nobody should ever see otherwise: a crypto wallet's seed phrase,
the passwords to the family accounts, where the deed to the house is, a letter
you could not say out loud.

The usual answers all fail somewhere. A password manager's emergency access
hands a company your secrets. A lawyer cannot hold a 2FA seed. "I'll just tell
my partner the master password" has no revocation, and stops being true the day
you change it.

ZDeadDrop does one thing. You **seal** things into a capsule for someone. While
you keep checking in, nothing happens. If you go quiet, reminders go out, the
people you trust are asked, a last countdown runs — and only then does the
capsule open, and only for the person you chose.

It is not a password manager, and it is not a will.

---

## A tour

### Setting up

A passphrase, a 24-word recovery sheet you prove you wrote down by typing three
words back, and a check-in rhythm you will actually keep.

| | |
| --- | --- |
| ![Welcome](docs/screenshots/welcome.png) | ![Recovery sheet](docs/screenshots/recovery-sheet.png) |

### The vigil

The home screen: how long until your next check-in, your capsules as wax seals,
and everything that would stop a real release. **I'm here** is one click.
**I'll be away** pauses everything for up to ninety days.

![Home](docs/screenshots/home.png)

### Sealing a capsule

Four questions, in the order you would think of them.

**What.** Drop files and folders anywhere on the window, or type secrets in
directly: notes, seed phrases (the checksum is verified, so a typo is caught
now rather than never), 2FA secrets, logins, recovery codes — or a whole
KeePass, Bitwarden, browser or `.env` export.

![What are you leaving?](docs/screenshots/wizard-what.png)

**Who.** Paste each person's public key, open their key file, or make one for
them. Every key shows its own seal and a code to read aloud over the phone, so
you can be sure it is really theirs. Add backups who receive it only if nobody
first in line claims it.

![Who receives it?](docs/screenshots/wizard-who.png)

**When.** How long you must be silent — drawn to scale — which trustees are
asked "are they gone?", how many must agree, and the final countdown.

![When should it open?](docs/screenshots/wizard-when.png)

**Seal.** The whole capsule as one sentence you can read out loud, two
rehearsals of it, and a button you hold for two seconds.

![Read it once, out loud](docs/screenshots/wizard-review.png)

### Handing out the pieces

A capsule's key is split: one piece for the relay, one for each trustee. No one
of them can open it alone. Send the relay its piece in one click; save each
trustee's piece to a file for them. Then the app forgets them all — nobody
should hold every piece, including you.

![Hand out the pieces](docs/screenshots/pieces.png)

### Living with it

Open a capsule to see who it is for, verify their keys, change its conditions,
export it, issue new pieces — or, behind typing its name and holding, release
it now or delete it. Right-click any capsule for the same, and click any code to
copy it.

| | |
| --- | --- |
| ![A capsule](docs/screenshots/capsule.png) | ![Right-click menu](docs/screenshots/context-menu.png) |

The **readiness** panel lists everything that would break a real release, worst
first, each with the one action that fixes it. The **rehearsal** runs the whole
release against a pretend clock — months in a moment, nothing real touched — so
you find out your setup is wrong while you can still fix it.

| | |
| --- | --- |
| ![Readiness](docs/screenshots/readiness.png) | ![Rehearsal](docs/screenshots/rehearsal.png) |

### Locked, and in daylight

| | |
| --- | --- |
| ![Locked](docs/screenshots/lock.png) | ![Parchment theme](docs/screenshots/parchment.png) |

---

## The seals

Every capsule has a wax seal, generated from its fingerprint: its identity, its
key pieces, and every recipient's key. Nobody compares thirty-two hex digits;
anyone notices that a picture changed. If someone swapped a recipient's key, the
seal would look different — so you tell your recipient what theirs looks like,
and they check.

![Twenty-four seals](docs/screenshots/seals.png)

The seal is also the status. The same capsule, from left to right: sealed,
stirring (a check-in is overdue), breaking (trustees asked, countdown running),
released, held, and frozen (the clock was moved, so nothing advances).

![One seal through every state](docs/screenshots/seal-states.png)

Shape carries the information, never colour alone, so the seals survive a
black-and-white printer and colour-blind eyes. Each also has a sentence for
reading aloud: *"moss wax · rosette · 9 arms · 2 rings · notch at 6"*.

---

## How release works

A single missed check-in does nothing at all. Release is a ladder, and every
rung has a way off it:

```
  check-in ──┬─ 30 days ─────→ due          one click clears it
             ├─ + 7 days ────→ grace        still silent, nothing sent
             ├─ reminders ───→ escalating   email or webhook, one-tap "I'm here"
             ├─ 45 days ─────→ polling      trustees asked, still no release
             ├─ countdown ───→ last call    one final message, one tap stops it
             └─ elapsed ─────→ released     relay's piece out; trustees send theirs
```

Reaching the bottom takes missing every rung **and** a quorum of people
independently agreeing you are gone. A trustee who answers "they are fine"
pushes it all back a month. Every number is yours to choose, per capsule.

**Nobody can release early.** The key needs the relay's piece *and* enough
trustees' pieces. The relay, holding everything it stores, cannot open a
capsule. Every trustee together cannot either. And a recipient still needs
their own private key on top.

**The relay is assumed to be hostile.** It never sees plaintext. It cannot fake
a check-in (they are signed by your vault), and cannot hide one without being
caught (every check-in returns a receipt your app verifies on the spot). Every
instruction you give it is signed and cannot be replayed. Run your own:
`docker compose -f crates/zdd-relay/compose.yaml up -d`.

**If someone forces you,** hold **Shift** while pressing *I'm here*. The
check-in looks exactly like any other, on screen and at the relay, but carries a
sealed flag only your trustees can read with `zdd trustee-check`.

---

## For the person receiving it

Someone left you something, and you have never used ZDeadDrop. You need the
capsule folder they gave you, your key file, and the `zdd` program.

Open **READ ME FIRST.txt** in the folder: it has the exact command. First check
the seal against what you were told it looks like:

```console
$ zdd claim --inspect --key alex.key "For Alex.zdd"

This capsule
  Seal             f7f9-bc5d-f578-b575
  Picture          moss wax · rosette · 9 arms · 2 rings · notch at 6
  Sealed on        2026-09-23
  Left to          2 people
  Size             2.0 MB

  If you were told what this seal should look like, check it now.
  A different picture means this is not the capsule they sealed.
```

Then open it, with the pieces the trustees sent you:

```console
$ zdd claim --key alex.key \
      --relay-share https://relay.example.org/v1/vault/241a-7116-9493-a222 \
      --trustee-share "For Alex — share for Sam.json" \
      --trustee-share "For Alex — share for Priya.json" \
      "For Alex.zdd"
```

It explains every step, keeps the folders as they were, and never overwrites a
file. Before the person who sealed it has really gone quiet, the relay refuses,
and `zdd` tells you so.

---

## Installing

Download the installer for your system from
**[zsync.eu/zdeaddrop](https://zsync.eu/zdeaddrop/)** or the
[GitHub releases](https://github.com/TheHolyOneZ/ZDeadDrop/releases):

| System | Download |
| --- | --- |
| Windows 10 / 11 | `.exe` installer or `.msi` |
| Linux | `.deb` (Debian, Ubuntu, Mint) or `.rpm` (Fedora, openSUSE) |

Each release also carries the `zdd` command line for every platform — send it
to the people you leave capsules for — and `SHA256SUMS.txt` to check your
download against.

Your vault is kept here, fully encrypted — back the folder up anywhere:

| System | Location |
| --- | --- |
| Windows | `%APPDATA%\ZDeadDrop` |
| Linux | `~/.local/share/zdeaddrop` |

Set `ZDD_VAULT` to keep it somewhere else.

### Building from source

```console
$ git clone https://github.com/TheHolyOneZ/ZDeadDrop && cd ZDeadDrop
$ pnpm install
$ pnpm tauri build                                  # the desktop app
$ cargo build --release -p zdd-cli -p zdd-relay     # the command line and the relay
```

You need a Rust toolchain and Node with pnpm; on Linux also `webkit2gtk-4.1`.
For development, `pnpm tauri dev`.

### The command line

| Command | |
| --- | --- |
| `zdd init` | create a vault |
| `zdd status`, `zdd checkin`, `zdd verify` | the vigil, from a server or a terminal |
| `zdd keygen` | make a key for someone who will receive a capsule |
| `zdd seal` | seal files for someone without the app |
| `zdd rehearse` | run the whole release against a pretend clock |
| `zdd trustee-check` | for trustees: was the latest check-in made freely? |
| `zdd claim` | open a capsule left to you |

---

## Status

Built, tested (524 tests), and exercised end to end by driving the real app:

| | |
| --- | --- |
| Vault: passphrase, recovery sheet, no-recovery policy, auto-lock | ✅ |
| Capsules: files, folders, typed secrets, password-manager exports | ✅ |
| Recipients: keys, seals, verification, backups, key replacement | ✅ |
| Release gate: relay piece + trustee quorum, reissue, change conditions, release now, delete | ✅ |
| Relay: signed check-ins with verified receipts, reminders, one-tap links, trustee questions, holds, vetoes, final countdown | ✅ |
| Duress check-in, readable by trustees | ✅ |
| Recipient command line, from files or straight from the relay | ✅ |
| Rehearsal, readiness, right-click menus, keyboard shortcuts | ✅ |

Designed for, but **not built yet**:

- a duress passphrase that opens a decoy vault;
- social recovery (trustees restoring your access) and hardware keys;
- periodic proof that each trustee still holds their piece;
- more than one relay;
- timestamp anchoring (RFC 3161 / OpenTimestamps) and network time checks —
  today the clock check is local, wall time against monotonic time.

---

## What it does not do

- **It is not a will.** It hands over data, never legal ownership.
- **It cannot detect death.** No software can. It measures silence against a
  threshold you chose; the trade-off between "safe against false alarms" and
  "fast in a real emergency" is yours to make.
- **It cannot help if your computer is already compromised** when you seal.
- **It cannot un-deliver.** If you wake from a coma after a release, the
  countdown and the trustees were your protection, and they are gone.
- **The relay decides when silence began.** It cannot release anything alone,
  but a relay that ignores your check-ins can start the final countdown; the
  countdown message, your trustees and their vetoes are the protection. Run
  your own if that matters to you.

---

## Keyboard

| | |
| --- | --- |
| `Ctrl N` | new capsule |
| `Ctrl L` | lock |
| `Ctrl ,` | settings |
| `Shift`-click *I'm here* | check in under duress |
| Right-click | actions for what is under the pointer |

---

## Under the hood

| Crate | |
| --- | --- |
| `zdd-core` | cryptography, capsule format, the release gate and the escalation ladder — no I/O, so the ladder is tested against a virtual clock |
| `zdd-seal` | the seal generator, byte-identical everywhere |
| `zdd-store` | the encrypted vault, blob store and tamper-evident event log |
| `zdd-import` | folders, KeePass, Bitwarden, browser exports, `.env`, 2FA seeds, seed phrases |
| `zdd-cli` | `zdd` |
| `zdd-relay` | the relay: Axum and SQLite, distroless, non-root |
| `src-tauri`, `src` | the desktop app: Tauri 2, React 19 |

XChaCha20-Poly1305 (streamed in 1 MiB chunks), X25519 key wrapping, Ed25519
signatures, Argon2id, Shamir over GF(256), BLAKE3.

The governing rule: every ambiguous condition resolves toward *not* releasing.
A bug here should lose a release, never leak a secret.

---

## Licence

GPL-3.0-or-later. Copyright © 2026 TheHolyOneZ.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; see the [licence](LICENSE) for details.
