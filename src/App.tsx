import { useCallback, useEffect, useRef, useState } from "react";

import * as api from "./lib/api";
import type { Capsule, Finding, Status, VaultSummary, Vigil } from "./lib/types";
import { CapsuleCard, NewCapsuleCard } from "./components/CapsuleCard";
import { CapsuleDrawer } from "./components/CapsuleDrawer";
import { About } from "./components/About";
import { CapsuleWizard } from "./components/CapsuleWizard";
import { LockScreen, Onboarding } from "./components/Gate";
import { ReadinessPanel } from "./components/ReadinessPanel";
import { RecoverySheet } from "./components/RecoverySheet";
import { RehearsalPanel } from "./components/RehearsalPanel";
import { Settings } from "./components/Settings";
import { SharesPanel } from "./components/Shares";
import { TitleBar } from "./components/TitleBar";
import { VigilBar } from "./components/VigilBar";
import {
  ContextMenuProvider,
  Modal,
  Spinner,
  ToastProvider,
  say,
  useContextMenu,
  useToast,
} from "./components/ui";

type Theme = "ink" | "parchment";

const MOD = /Mac|iPhone|iPad/.test(navigator.userAgent) ? "⌘" : "Ctrl";
const THEME_KEY = "zdd.theme";

function initialTheme(): Theme {
  try {
    const param = new URLSearchParams(window.location.search).get("theme");
    if (param === "ink" || param === "parchment") return param;
    const stored = window.localStorage.getItem(THEME_KEY);
    if (stored === "ink" || stored === "parchment") return stored;
  } catch {}
  return "ink";
}

export default function App() {
  return (
    <ToastProvider>
      <ContextMenuProvider>
        <Shell />
      </ContextMenuProvider>
    </ToastProvider>
  );
}

function Shell() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [status, setStatus] = useState<Status | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [about, setAbout] = useState(false);

  useEffect(() => {
    document.documentElement.dataset["theme"] = theme;
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {}
  }, [theme]);

  const refreshStatus = useCallback(() => {
    api.status().then(setStatus, (e) => setFatal(say(e)));
  }, []);
  useEffect(refreshStatus, [refreshStatus]);

  useEffect(() => {
    let off: (() => void) | undefined;
    void api.listen("vault-locked", refreshStatus).then((f) => (off = f));
    return () => off?.();
  }, [refreshStatus]);

  const toggleTheme = () => setTheme((t) => (t === "ink" ? "parchment" : "ink"));

  if (fatal) {
    return (
      <div className="gate grain">
        <div className="gate__panel">
          <h1 className="gate__title serif">ZDeadDrop could not start</h1>
          <p className="gate__lead">{fatal}</p>
        </div>
      </div>
    );
  }

  if (!status) {
    return (
      <div className="app">
        <TitleBar
          vault={null}
          theme={theme}
          onToggleTheme={toggleTheme}
          onAbout={() => setAbout(true)}
        />
        <div className="gate">
          <Spinner label="Opening" />
        </div>
      </div>
    );
  }

  return (
    <div className="app grain">
      {!status.exists ? (
        <>
          <TitleBar
            vault={null}
            theme={theme}
            onToggleTheme={toggleTheme}
            onAbout={() => setAbout(true)}
          />
          <Onboarding onDone={refreshStatus} />
        </>
      ) : !status.unlocked ? (
        <>
          <TitleBar
            vault={null}
            theme={theme}
            onToggleTheme={toggleTheme}
            onAbout={() => setAbout(true)}
          />
          <LockScreen status={status} onUnlocked={refreshStatus} />
        </>
      ) : (
        <Vault
          theme={theme}
          onToggleTheme={toggleTheme}
          onLocked={refreshStatus}
          onAbout={() => setAbout(true)}
        />
      )}
      {about && <About onClose={() => setAbout(false)} />}
    </div>
  );
}

type Overlay =
  | { kind: "wizard" }
  | { kind: "capsule"; id: string; action?: "release" | "delete" | "reissue" }
  | { kind: "settings" }
  | { kind: "sheet" }
  | { kind: "shares"; id: string };

function Vault({
  theme,
  onToggleTheme,
  onLocked,
  onAbout,
}: {
  theme: Theme;
  onToggleTheme: () => void;
  onLocked: () => void;
  onAbout: () => void;
}) {
  const toast = useToast();
  const [vigil, setVigil] = useState<Vigil | null>(null);
  const [capsules, setCapsules] = useState<Capsule[] | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [vault, setVault] = useState<VaultSummary | null>(null);
  const [checking, setChecking] = useState(false);
  const [overlay, setOverlay] = useState<Overlay | null>(null);
  const rehearsalRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(() => {
    Promise.all([api.loadVigil(), api.loadCapsules(), api.loadFindings(), api.loadVault()]).then(
      ([v, c, f, s]) => {
        setVigil(v);
        setCapsules(c);
        setFindings(f);
        setVault(s);
      },
      (e) => {
        if (e instanceof api.Refusal && e.locked) onLocked();
        else toast(say(e), "bad");
      },
    );
  }, [onLocked, toast]);

  useEffect(refresh, [refresh]);

  useEffect(() => {
    const t = window.setInterval(refresh, 60_000);
    return () => window.clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    let last = 0;
    const ping = () => {
      const now = Date.now();
      if (now - last > 20_000) {
        last = now;
        void api.touch().catch(() => {});
      }
    };
    window.addEventListener("pointerdown", ping);
    window.addEventListener("keydown", ping);
    return () => {
      window.removeEventListener("pointerdown", ping);
      window.removeEventListener("keydown", ping);
    };
  }, []);

  const menu = useContextMenu();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      if ((e.target as HTMLElement | null)?.closest("input, textarea")) return;
      const k = e.key.toLowerCase();
      if (k === "n" && !overlay) {
        e.preventDefault();
        setOverlay({ kind: "wizard" });
      } else if (k === "l") {
        e.preventDefault();
        void lockNow();
      } else if (k === ",") {
        e.preventDefault();
        setOverlay({ kind: "settings" });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const capsuleMenu = (e: React.MouseEvent, c: Capsule) =>
    menu(e, [
      { label: "Open", onSelect: () => setOverlay({ kind: "capsule", id: c.id }) },
      {
        label: "Copy seal code",
        onSelect: () =>
          api.copyText(c.fingerprint).then(
            () => toast(`Seal code copied: ${c.fingerprint}`, "good"),
            (err) => toast(say(err), "bad"),
          ),
      },
      "separator",
      {
        label: c.releasedAt ? "Already released" : "Export for recipients…",
        disabled: c.releasedAt !== null,
        onSelect: () =>
          api.exportCapsule(c.id).then(
            (where) => {
              if (where) {
                toast("Exported. It is encrypted — safe to give them now.", "good");
                refresh();
              }
            },
            (err) => toast(say(err), "bad"),
          ),
      },
      c.sharesPending
        ? {
            label: "Hand out the pieces…",
            onSelect: () => setOverlay({ kind: "shares", id: c.id }),
          }
        : {
            label: "Issue new pieces…",
            disabled: c.releasedAt !== null,
            onSelect: () => setOverlay({ kind: "capsule", id: c.id, action: "reissue" }),
          },
      "separator",
      {
        label: "Release now…",
        danger: true,
        disabled: c.releasedAt !== null,
        onSelect: () => setOverlay({ kind: "capsule", id: c.id, action: "release" }),
      },
      {
        label: "Delete…",
        danger: true,
        onSelect: () => setOverlay({ kind: "capsule", id: c.id, action: "delete" }),
      },
    ]);

  const lockNow = async () => {
    await api.lock().catch(() => {});
    onLocked();
  };

  const checkIn = (underDuress: boolean) => {
    setChecking(true);
    api
      .checkIn(underDuress)
      .then(
        (v) => {
          setVigil(v);
          toast(
            v.relay?.lastError
              ? "Checked in here — but the relay did not confirm it."
              : "Checked in. See you next time.",
            v.relay?.lastError ? "bad" : "good",
          );
          refresh();
        },
        (e) => toast(say(e), "bad"),
      )
      .finally(() => window.setTimeout(() => setChecking(false), 1200));
  };

  const act = (f: Finding) => {
    const t = f.target ?? "";
    if (t === "sheet") setOverlay({ kind: "sheet" });
    else if (t === "relay") setOverlay({ kind: "settings" });
    else if (t === "checkin") checkIn(false);
    else if (t === "clock")
      document.querySelector(".vigil")?.scrollIntoView({ behavior: "smooth" });
    else if (t === "rehearse")
      rehearsalRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    else if (t.startsWith("capsule:")) setOverlay({ kind: "capsule", id: t.slice(8) });
    else if (t.startsWith("shares:")) {
      const id = t.slice(7);
      const c = capsules?.find((x) => x.id === id);
      if (c?.sharesPending) setOverlay({ kind: "shares", id });
      else setOverlay({ kind: "capsule", id });
    } else if (t.startsWith("export:")) {
      api.exportCapsule(t.slice(7)).then(
        (where) => {
          if (where) {
            toast("Exported. It is encrypted — safe to give them now.", "good");
            refresh();
          }
        },
        (e) => toast(say(e), "bad"),
      );
    }
  };

  const biggest = capsules?.reduce<Capsule | null>(
    (a, c) => (c.quorum && (!a || (a.quorum?.of ?? 0) < c.quorum.of) ? c : a),
    null,
  );

  return (
    <>
      <TitleBar
        vault={vault}
        theme={theme}
        onToggleTheme={onToggleTheme}
        onLock={() => void lockNow()}
        onSettings={() => setOverlay({ kind: "settings" })}
        onAbout={onAbout}
      />

      <main className="sheet">
        {vigil && (
          <VigilBar
            vigil={vigil}
            onRelay={() => setOverlay({ kind: "settings" })}
            checking={checking}
            onCheckIn={checkIn}
            onHold={(d) =>
              api.setHold(d).then(
                (v) => {
                  setVigil(v);
                  toast(`Held for ${api.plural(d, "day")}. Safe travels.`, "good");
                  refresh();
                },
                (e) => toast(say(e), "bad"),
              )
            }
            onEndHold={() =>
              api.clearHold().then(
                (v) => {
                  setVigil(v);
                  refresh();
                },
                (e) => toast(say(e), "bad"),
              )
            }
            onAcknowledge={() =>
              api.acknowledgeClock().then(
                (v) => {
                  setVigil(v);
                  refresh();
                },
                (e) => toast(say(e), "bad"),
              )
            }
          />
        )}

        <section className="capsules" aria-labelledby="capsules-rubric">
          <h2 className="rubric" id="capsules-rubric">
            Capsules
            {capsules && (
              <span className="rubric__count">{api.plural(capsules.length, "capsule")}</span>
            )}
          </h2>

          {capsules && capsules.length === 0 ? (
            <div className="empty">
              <div className="empty__art" aria-hidden="true">
                <svg viewBox="0 0 120 120" width="120" height="120">
                  <circle
                    cx="60"
                    cy="60"
                    r="44"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.2"
                    strokeDasharray="3 6"
                  />
                  <circle
                    cx="60"
                    cy="60"
                    r="30"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1"
                    opacity="0.5"
                  />
                  <path
                    d="M60 44v32M44 60h32"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <div className="empty__copy">
                <h3 className="serif">Nothing sealed yet</h3>
                <p className="faint">
                  A capsule holds files, notes, passwords, seed phrases — whatever someone will
                  need. You choose who receives it and how long your silence must last before it
                  opens.
                </p>
                <button
                  type="button"
                  className="btn btn--primary btn--lg"
                  onClick={() => setOverlay({ kind: "wizard" })}
                >
                  Seal your first capsule
                </button>
              </div>
            </div>
          ) : (
            <div
              className="capsules__wall"
              onContextMenu={(e) =>
                menu(e, [
                  {
                    label: "New capsule…",
                    hint: `${MOD} N`,
                    onSelect: () => setOverlay({ kind: "wizard" }),
                  },
                  {
                    label: "Settings",
                    hint: `${MOD} ,`,
                    onSelect: () => setOverlay({ kind: "settings" }),
                  },
                  { label: "Lock", hint: `${MOD} L`, onSelect: () => void lockNow() },
                  "separator",
                  { label: "About ZDeadDrop", onSelect: onAbout },
                ])
              }
            >
              {capsules?.map((c) => (
                <CapsuleCard
                  key={c.id}
                  capsule={c}
                  onOpen={(id) => setOverlay({ kind: "capsule", id })}
                  onMenu={(e) => capsuleMenu(e, c)}
                />
              ))}
              <NewCapsuleCard onClick={() => setOverlay({ kind: "wizard" })} />
            </div>
          )}
        </section>

        {capsules && capsules.length > 0 && <ReadinessPanel findings={findings} onAct={act} />}

        <div ref={rehearsalRef}>
          <RehearsalPanel
            key={biggest?.id ?? "default"}
            initialQuorum={biggest?.quorum?.need ?? 3}
            initialTrustees={biggest?.quorum?.of ?? 5}
            {...(biggest
              ? { silenceDays: biggest.silenceDays, countdownDays: biggest.countdownDays }
              : {})}
          />
        </div>
      </main>

      {overlay?.kind === "wizard" && vault && (
        <CapsuleWizard vault={vault} onClose={() => setOverlay(null)} onSealed={refresh} />
      )}
      {overlay?.kind === "capsule" && (
        <CapsuleDrawer
          id={overlay.id}
          {...(overlay.action ? { initialAction: overlay.action } : {})}
          onClose={() => setOverlay(null)}
          onChanged={refresh}
        />
      )}
      {overlay?.kind === "settings" && vault && (
        <Settings
          vault={vault}
          vigil={vigil}
          onClose={() => setOverlay(null)}
          onChanged={refresh}
          onRecoverySheet={() => setOverlay({ kind: "sheet" })}
          onAbout={() => {
            setOverlay(null);
            onAbout();
          }}
        />
      )}
      {overlay?.kind === "sheet" && (
        <RecoverySheet
          onDone={() => {
            setOverlay(null);
            toast("Recovery sheet added. Keep the paper safe.", "good");
            refresh();
          }}
          onSkip={() => setOverlay(null)}
        />
      )}
      {overlay?.kind === "shares" && (
        <Modal title="Hand out the pieces" kicker="Shares" onClose={() => setOverlay(null)} wide>
          <SharesPanel
            id={overlay.id}
            onFinished={() => {
              setOverlay(null);
              refresh();
            }}
          />
        </Modal>
      )}
    </>
  );
}
