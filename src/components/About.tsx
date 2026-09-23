import { useEffect, useState } from "react";

import logo from "../assets/logo.png";
import * as api from "../lib/api";
import { Drawer, say, useToast } from "./ui";

const LINKS: { which: api.LinkName; label: string; url: string; hint: string }[] = [
  {
    which: "home",
    label: "ZDeadDrop homepage",
    url: "zsync.eu/zdeaddrop",
    hint: "Downloads, updates and guides",
  },
  {
    which: "source",
    label: "Source code",
    url: "github.com/TheHolyOneZ/ZDeadDrop",
    hint: "Read it, audit it, build it yourself",
  },
  {
    which: "author",
    label: "TheHolyOneZ on GitHub",
    url: "github.com/TheHolyOneZ",
    hint: "The author",
  },
  {
    which: "projects",
    label: "More projects like this",
    url: "zsync.eu",
    hint: "Other ZSync tools",
  },
  {
    which: "mods",
    label: "Game mods",
    url: "zlogic.eu",
    hint: "ZLogic",
  },
];

const STACK = [
  ["Core", "Rust — XChaCha20-Poly1305, X25519, Ed25519, Argon2id, Shamir, BLAKE3"],
  ["App", "Tauri 2 · React 19 · TypeScript"],
  ["Storage", "SQLite, every row sealed separately"],
  ["Relay", "Rust · Axum · SQLite, self-hostable with Docker"],
];

export function About({ onClose }: { onClose: () => void }) {
  const toast = useToast();
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    api.appVersion().then(setVersion, () => {});
  }, []);

  const open = (which: api.LinkName) => void api.openLink(which).catch((e) => toast(say(e), "bad"));

  return (
    <Drawer onClose={onClose} label="About ZDeadDrop">
      <div className="dossier about">
        <header className="about__head">
          <img className="about__logo" src={logo} alt="" width={112} height={112} />
          <div>
            <h2 className="serif about__title">ZDeadDrop</h2>
            <p className="faint mono">{version ? `version ${version}` : ""}</p>
          </div>
        </header>

        <p className="about__lead">
          A local-first digital dead-man's switch and encrypted legacy vault. Seal files and secrets
          for the people you choose. While you check in, nothing happens. If you go silent,
          reminders go out, your trustees are asked, a last countdown runs — and only then does
          anything open, and only for them.
        </p>
        <p className="faint about__note">
          Everything is encrypted on this machine. No relay, trustee or server — including ours —
          can read what you seal, and no single one of them can open it early.
        </p>

        <section className="dossier__section">
          <h3 className="rubric">Built with</h3>
          <dl className="about__stack">
            {STACK.map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="dossier__section">
          <h3 className="rubric">Links</h3>
          <ul className="about__links">
            {LINKS.map((l) => (
              <li key={l.which}>
                <button type="button" className="about__link" onClick={() => open(l.which)}>
                  <span className="about__linklabel">{l.label}</span>
                  <span className="mono about__url">{l.url}</span>
                  <span className="faint about__hint">{l.hint}</span>
                  <span className="about__arrow" aria-hidden="true">
                    ↗
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section className="dossier__section">
          <h3 className="rubric">Author</h3>
          <p>
            Made by <strong>TheHolyOneZ</strong>.
          </p>
          <p className="faint about__licence">
            Free software under the GNU General Public License, version 3 or later. Copyright © 2026
            TheHolyOneZ. It comes with no warranty — which is why it is built to be read.
          </p>
        </section>
      </div>
    </Drawer>
  );
}
