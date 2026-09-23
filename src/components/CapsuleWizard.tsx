import { useCallback, useEffect, useRef, useState } from "react";

import * as api from "../lib/api";
import type {
  ItemPreview,
  ItemSpec,
  KeyInfo,
  Progress,
  RehearsalReport,
  VaultSummary,
} from "../lib/types";
import { HoldToConfirm } from "./HoldToConfirm";
import { Seal } from "./Seal";
import { SharesPanel } from "./Shares";
import { Chips, Stepper, say, useToast, CopyCode } from "./ui";

interface Item {
  spec: ItemSpec;
  preview: ItemPreview;
}

interface Person {
  label: string;
  keyText: string;
  key: KeyInfo | null;
  keyError: string | null;
  verified: boolean;
  backup: boolean;
}

const blankPerson = (): Person => ({
  label: "",
  keyText: "",
  key: null,
  keyError: null,
  verified: false,
  backup: false,
});

type SecretKind = "note" | "seed" | "totp" | "login" | "codes";

const KIND_GLYPH: Record<ItemPreview["kind"], string> = {
  file: "▤",
  folder: "▦",
  note: "✎",
  seed: "⁂",
  totp: "◷",
  codes: "#",
  login: "⚿",
};

const STEPS = ["What", "Who", "When", "Seal"] as const;

export function CapsuleWizard({
  vault,
  onClose,
  onSealed,
}: {
  vault: VaultSummary;
  onClose: () => void;
  onSealed: () => void;
}) {
  const toast = useToast();
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [items, setItems] = useState<Item[]>([]);
  const [adding, setAdding] = useState<SecretKind | "import" | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busyPaths, setBusyPaths] = useState(0);
  const [people, setPeople] = useState<Person[]>([blankPerson()]);
  const [backupWindow, setBackupWindow] = useState(60);
  const floor = vault.checkinIntervalDays + vault.graceDays;
  const [silence, setSilence] = useState(Math.max(45, floor + 8));
  const [countdown, setCountdown] = useState(3);
  const [trustees, setTrustees] = useState<{ name: string; contact: string }[]>(
    Array.from({ length: 3 }, () => ({ name: "", contact: "" })),
  );
  const [quorum, setQuorum] = useState(2);
  const [sealing, setSealing] = useState<Progress | null>(null);
  const [sealedId, setSealedId] = useState<string | null>(null);
  const [skipped, setSkipped] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const body = useRef<HTMLElement>(null);

  useEffect(() => {
    body.current?.scrollTo({ top: 0 });
  }, [step]);

  const addSpec = useCallback(async (spec: ItemSpec): Promise<string | null> => {
    try {
      const preview = await api.previewItem(spec);
      setItems((xs) => [...xs, { spec, preview }]);
      return null;
    } catch (e) {
      return say(e);
    }
  }, []);

  const addPaths = useCallback(
    async (paths: string[]) => {
      setBusyPaths((n) => n + paths.length);
      for (const path of paths) {
        const problem = await addSpec({ type: "path", path });
        if (problem) toast(problem, "bad");
        setBusyPaths((n) => n - 1);
      }
      if (!name && paths.length === 1) {
        const base = paths[0]!.split(/[\\/]/).pop() ?? "";
        setName(base.replace(/\.[^.]+$/, ""));
      }
    },
    [addSpec, name, toast],
  );

  useEffect(() => {
    if (step !== 0) return;
    let off: (() => void) | undefined;
    void api
      .onFileDrop((e) => {
        if (e.kind === "over") setDragging(true);
        else if (e.kind === "leave") setDragging(false);
        else {
          setDragging(false);
          void addPaths(e.paths);
        }
      })
      .then((f) => (off = f));
    return () => off?.();
  }, [step, addPaths]);

  const pick = async (folders: boolean) => {
    try {
      const paths = await api.pickPaths(folders);
      if (paths.length) await addPaths(paths);
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const setPerson = (i: number, patch: Partial<Person>) =>
    setPeople((ps) => ps.map((p, j) => (j === i ? { ...p, ...patch } : p)));

  const readKey = async (i: number, text: string) => {
    setPerson(i, { keyText: text, key: null, keyError: null, verified: false });
    if (!text.trim()) return;
    try {
      setPerson(i, { key: await api.inspectKey(text), keyError: null });
    } catch (e) {
      setPerson(i, { keyError: say(e) });
    }
  };

  const openKey = async (i: number) => {
    try {
      const key = await api.pickKeyFile();
      if (key) setPerson(i, { key, keyText: key.publicKey, keyError: null, verified: false });
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const makeKey = async (i: number) => {
    const label = people[i]!.label.trim() || "Recipient";
    try {
      const key = await api.generateRecipientKey(label);
      if (key) {
        setPerson(i, { key, keyText: key.publicKey, keyError: null, verified: true });
        toast(`Key file written for ${label}. Give it to them, then delete your copy.`, "good");
      }
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const problems = (s: number): string | null => {
    if (s === 0) {
      if (!name.trim()) return "Give the capsule a name.";
      if (items.length === 0) return "Add something to seal.";
    }
    if (s === 1) {
      if (people.length === 0) return "Add someone to receive it.";
      for (const p of people) {
        if (!p.label.trim()) return "Every recipient needs a name.";
        if (!p.key) return `${p.label || "A recipient"} needs a key.`;
      }
      if (people.every((p) => p.backup)) return "At least one person must be first in line.";
    }
    if (s === 2) {
      const named = trustees.filter((t) => t.name.trim());
      if (named.length === 1)
        return "One trustee cannot form a quorum. Add a second, or remove them.";
      if (named.length !== trustees.length) return "Every trustee needs a name.";
      if (silence <= floor) return `The wait must be longer than ${floor} days.`;
    }
    return null;
  };

  const next = () => {
    const p = problems(step);
    if (p) {
      setError(p);
      return;
    }
    setError(null);
    setStep((s) => s + 1);
  };

  const namedTrustees = trustees.map((t) => t.name.trim()).filter(Boolean);
  const effectiveQuorum = namedTrustees.length >= 2 ? Math.min(quorum, namedTrustees.length) : 0;
  const [best, setBest] = useState<RehearsalReport | null>(null);
  const [likely, setLikely] = useState<RehearsalReport | null>(null);

  useEffect(() => {
    if (step !== 3) return;
    const t = namedTrustees.length;
    void api
      .rehearse(effectiveQuorum, t, "all-answer", t, silence, countdown)
      .then(setBest, () => {});
    if (t > 0) {
      void api
        .rehearse(
          effectiveQuorum,
          t,
          "some-answer",
          Math.max(0, effectiveQuorum - 1),
          silence,
          countdown,
        )
        .then(setLikely, () => {});
    } else setLikely(null);
  }, [step]);

  const seal = async () => {
    setError(null);
    setSealing({ phase: "sealing", done: 0, total: 1 });
    const off = await api.onSealProgress(setSealing);
    try {
      const sealed = await api.sealCapsule({
        name: name.trim(),
        note: note.trim() || null,
        items: items.map((i) => i.spec),
        recipients: people.map((p) => ({
          label: p.label.trim(),
          publicKey: p.key!.publicKey,
          tier: p.backup ? 1 : 0,
          claimWindowDays: p.backup ? 0 : people.some((q) => q.backup) ? backupWindow : 0,
          verified: p.verified,
        })),
        trustees: trustees
          .filter((t) => t.name.trim())
          .map((t) => ({ name: t.name.trim(), contact: t.contact.trim() || null })),
        quorum: effectiveQuorum,
        silenceDays: silence,
        countdownDays: countdown,
      });
      setSkipped(sealed.skipped);
      setSealedId(sealed.id);
      setStep(4);
      onSealed();
    } catch (e) {
      setError(say(e));
    } finally {
      off();
      setSealing(null);
    }
  };

  const totalBytes = items.reduce((n, i) => n + i.preview.bytes, 0);
  const totalFiles = items.reduce((n, i) => n + i.preview.files, 0);
  const first = people.filter((p) => !p.backup).map((p) => p.label.trim() || "them");
  const backups = people.filter((p) => p.backup).map((p) => p.label.trim() || "them");
  const sentence =
    `If you don't check in for ${silence} days` +
    (effectiveQuorum
      ? `, and ${effectiveQuorum} of your ${namedTrustees.length} trustees agree you're gone`
      : "") +
    `, “${name.trim() || "this capsule"}” opens for ${listOf(first)} after a ${countdown}-day final countdown` +
    (backups.length
      ? ` — and for ${listOf(backups)} if nobody first in line claims it within ${backupWindow} days.`
      : ".");

  return (
    <div className="wizard grain" role="dialog" aria-modal="true" aria-label="New capsule">
      <header className="wizard__head">
        <button
          type="button"
          className="btn btn--ghost btn--small"
          onClick={onClose}
          disabled={!!sealing}
        >
          {step === 4 ? "Close" : "Cancel"}
        </button>
        <ol className="wizard__rail">
          {STEPS.map((label, i) => (
            <li key={label} data-on={i === step} data-done={i < step}>
              <span className="wizard__num">{i < step ? "✓" : i + 1}</span>
              {label}
            </li>
          ))}
        </ol>
        <span />
      </header>

      <main className="wizard__body" ref={body}>
        {step === 0 && (
          <section className="wstep">
            <h1 className="wstep__title serif">What are you leaving?</h1>
            <div className="wstep__grid">
              <label className="field">
                <span className="field__label">Capsule name</span>
                <input
                  className="input input--lg"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="For Alex"
                  autoFocus
                />
                <span className="field__hint">Only you and the recipients ever see this.</span>
              </label>
              <label className="field">
                <span className="field__label">A message for them (optional)</span>
                <textarea
                  className="input"
                  rows={3}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Shown before anything is opened."
                />
              </label>
            </div>

            <div className="dropzone" data-over={dragging}>
              <div className="dropzone__art" aria-hidden="true">
                <svg viewBox="0 0 48 48" width="40" height="40">
                  <path
                    d="M24 32V10m0 0-8 8m8-8 8 8"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M8 30v6a4 4 0 0 0 4 4h24a4 4 0 0 0 4-4v-6"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <p className="dropzone__title">Drop files or folders anywhere on this window</p>
              <p className="dropzone__sub faint">
                They are read and encrypted only when you seal. Nothing is copied before that.
              </p>
              <div className="dropzone__buttons">
                <button type="button" className="btn btn--small" onClick={() => void pick(false)}>
                  Choose files
                </button>
                <button type="button" className="btn btn--small" onClick={() => void pick(true)}>
                  Choose a folder
                </button>
              </div>
            </div>

            <div className="secretbar">
              <span className="secretbar__label faint">Or type a secret in directly:</span>
              {(
                [
                  ["note", "Note"],
                  ["seed", "Seed phrase"],
                  ["totp", "2FA secret"],
                  ["login", "Login"],
                  ["codes", "Recovery codes"],
                  ["import", "Password manager export"],
                ] as [SecretKind | "import", string][]
              ).map(([k, label]) => (
                <button
                  key={k}
                  type="button"
                  className="chip chip--small"
                  data-on={adding === k}
                  onClick={() => setAdding(adding === k ? null : k)}
                >
                  {label}
                </button>
              ))}
            </div>

            {adding === "import" ? (
              <ImportEditor
                onCancel={() => setAdding(null)}
                onAdd={async (spec) => {
                  const problem = await addSpec(spec);
                  if (!problem) setAdding(null);
                  return problem;
                }}
              />
            ) : (
              adding && (
                <SecretEditor
                  kind={adding}
                  onCancel={() => setAdding(null)}
                  onAdd={async (spec) => {
                    const problem = await addSpec(spec);
                    if (!problem) setAdding(null);
                    return problem;
                  }}
                />
              )
            )}

            {(items.length > 0 || busyPaths > 0) && (
              <ul className="items">
                {items.map((item, i) => (
                  <li key={i} className="item">
                    <span className="item__glyph" aria-hidden="true">
                      {KIND_GLYPH[item.preview.kind]}
                    </span>
                    <span className="item__text">
                      <strong>{item.preview.title}</strong>
                      <span className="faint">
                        {item.preview.kind === "folder"
                          ? `${api.plural(item.preview.files, "file")} · ${api.bytes(item.preview.bytes)}`
                          : item.preview.kind === "file"
                            ? api.bytes(item.preview.bytes)
                            : item.preview.detail}
                        {item.preview.skipped.length > 0 && (
                          <span className="item__skipped" title={item.preview.skipped.join("\n")}>
                            {" "}
                            · {item.preview.skipped.length} left out (hover to see)
                          </span>
                        )}
                      </span>
                    </span>
                    <button
                      type="button"
                      className="iconbtn"
                      aria-label={`Remove ${item.preview.title}`}
                      onClick={() => setItems((xs) => xs.filter((_, j) => j !== i))}
                    >
                      <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true">
                        <path
                          d="M2 2l6 6M8 2l-6 6"
                          stroke="currentColor"
                          strokeWidth="1.3"
                          strokeLinecap="round"
                        />
                      </svg>
                    </button>
                  </li>
                ))}
                {busyPaths > 0 && (
                  <li className="item item--busy faint">
                    Reading {api.plural(busyPaths, "item")}…
                  </li>
                )}
                <li className="items__total faint">
                  {api.plural(totalFiles, "item")} · {api.bytes(totalBytes)}
                </li>
              </ul>
            )}
          </section>
        )}

        {step === 1 && (
          <section className="wstep">
            <h1 className="wstep__title serif">Who receives it?</h1>
            <p className="wstep__lead">
              Each person needs a ZDeadDrop key. They make one with{" "}
              <span className="mono">zdd keygen</span> and send you the public half — or, if they
              never will, make one for them here and hand them the file.
            </p>

            <div className="people">
              {people.map((p, i) => (
                <article key={i} className="person">
                  <div className="person__main">
                    <label className="field">
                      <span className="field__label">Name</span>
                      <input
                        className="input"
                        value={p.label}
                        onChange={(e) => setPerson(i, { label: e.target.value })}
                        placeholder="Their name"
                      />
                    </label>
                    <label className="field">
                      <span className="field__label">Their public key</span>
                      <textarea
                        className="input mono person__key"
                        rows={2}
                        value={p.keyText}
                        onChange={(e) => void readKey(i, e.target.value)}
                        placeholder="Paste it here"
                        spellCheck={false}
                      />
                    </label>
                    <div className="person__buttons">
                      <button
                        type="button"
                        className="btn btn--small btn--ghost"
                        onClick={() => void openKey(i)}
                      >
                        Open their key file
                      </button>
                      <button
                        type="button"
                        className="btn btn--small btn--ghost"
                        onClick={() => void makeKey(i)}
                      >
                        Make a key for them
                      </button>
                      {people.length > 1 && (
                        <button
                          type="button"
                          className="btn btn--small btn--ghost person__remove"
                          onClick={() => setPeople((ps) => ps.filter((_, j) => j !== i))}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                    {p.keyError && <p className="form-error">{p.keyError}</p>}
                    {p.key?.wasPrivate && (
                      <p className="form-error">
                        That was {p.label.trim() || "their"}'s <strong>private</strong> key file.
                        Only the public half was used — but the file has now been handled by someone
                        other than them. Tell them to keep it secret, or better, make a fresh key.
                      </p>
                    )}
                    {people.length > 1 && (
                      <label className="check check--small">
                        <input
                          type="checkbox"
                          checked={p.backup}
                          onChange={(e) => setPerson(i, { backup: e.target.checked })}
                        />
                        <span>
                          Backup — receives it only if nobody first in line claims it in time
                        </span>
                      </label>
                    )}
                  </div>

                  <div className="person__seal" data-empty={!p.key}>
                    {p.key ? (
                      <>
                        <Seal seed={p.key.sealSeed} state="sealed" size={96} />
                        <CopyCode text={p.key.fingerprint} label="Key code" />
                        <span className="person__figure faint">{p.key.figure}</span>
                        <label className="check check--small">
                          <input
                            type="checkbox"
                            checked={p.verified}
                            onChange={(e) => setPerson(i, { verified: e.target.checked })}
                          />
                          <span>I read this code to {p.label.trim() || "them"} and it matched</span>
                        </label>
                      </>
                    ) : (
                      <span className="faint">Their key's seal appears here</span>
                    )}
                  </div>
                </article>
              ))}
            </div>

            <div className="wstep__row">
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => setPeople((ps) => [...ps, blankPerson()])}
              >
                + Add another person
              </button>
              {people.some((p) => p.backup) && (
                <div className="inline-field">
                  <span className="faint">Backups get it if nobody claims within</span>
                  <Stepper
                    label="days before backups"
                    value={backupWindow}
                    min={7}
                    max={365}
                    onChange={setBackupWindow}
                    suffix="days"
                  />
                </div>
              )}
            </div>
          </section>
        )}

        {step === 2 && (
          <section className="wstep">
            <h1 className="wstep__title serif">When should it open?</h1>

            <div className="when">
              <div className="when__block">
                <h3 className="when__head">Silence</h3>
                <p className="faint">
                  How long you must be unreachable before your trustees are even asked.
                </p>
                <div className="when__slider">
                  <input
                    type="range"
                    min={floor + 1}
                    max={365}
                    value={silence}
                    onChange={(e) => setSilence(Number(e.target.value))}
                    aria-label="Days of silence"
                    style={
                      {
                        "--fill": `${((silence - floor - 1) / Math.max(1, 364 - floor)) * 100}%`,
                      } as React.CSSProperties
                    }
                  />
                  <span className="when__value serif">{silence}</span>
                  <span className="faint">days</span>
                </div>
                <Timeline
                  interval={vault.checkinIntervalDays}
                  grace={vault.graceDays}
                  silence={silence}
                  countdown={countdown}
                  trustees={namedTrustees.length}
                />
              </div>

              <div className="when__block">
                <h3 className="when__head">Trustees</h3>
                <p className="faint">
                  People who are asked “are they gone?” — they never see what is inside. With
                  trustees, no single person, and not the relay, can open this alone. Give the relay
                  a way to reach them and it asks them itself when the time comes.
                </p>
                <ul className="trustees">
                  {trustees.map((t, i) => (
                    <li key={i}>
                      <span className="trustees__n">{i + 1}</span>
                      <input
                        className="input"
                        value={t.name}
                        placeholder="Name"
                        onChange={(e) =>
                          setTrustees((ts) =>
                            ts.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)),
                          )
                        }
                      />
                      <input
                        className="input trustees__contact"
                        value={t.contact}
                        placeholder="Email or https link (optional)"
                        onChange={(e) =>
                          setTrustees((ts) =>
                            ts.map((x, j) => (j === i ? { ...x, contact: e.target.value } : x)),
                          )
                        }
                      />
                      <button
                        type="button"
                        className="iconbtn"
                        aria-label="Remove trustee"
                        onClick={() => {
                          setTrustees((ts) => ts.filter((_, j) => j !== i));
                          setQuorum((q) => Math.min(q, Math.max(2, trustees.length - 1)));
                        }}
                      >
                        <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true">
                          <path
                            d="M2 2l6 6M8 2l-6 6"
                            stroke="currentColor"
                            strokeWidth="1.3"
                            strokeLinecap="round"
                          />
                        </svg>
                      </button>
                    </li>
                  ))}
                </ul>
                <div className="wstep__row">
                  <button
                    type="button"
                    className="btn btn--small btn--ghost"
                    onClick={() => setTrustees((ts) => [...ts, { name: "", contact: "" }])}
                    disabled={trustees.length >= 12}
                  >
                    + Add a trustee
                  </button>
                  {trustees.length >= 2 && (
                    <div className="inline-field">
                      <Stepper
                        label="trustees needed"
                        value={Math.min(quorum, trustees.length)}
                        min={2}
                        max={trustees.length}
                        onChange={setQuorum}
                      />
                      <span className="faint">of {trustees.length} must agree</span>
                    </div>
                  )}
                </div>
                {trustees.length === 0 && (
                  <p className="warnline">
                    No trustees: whoever runs the relay could open this by declaring you silent.
                  </p>
                )}
                {trustees.length >= 2 && Math.min(quorum, trustees.length) === trustees.length && (
                  <p className="warnline">
                    Every trustee must agree. If one dies or loses their piece, this can never open.
                  </p>
                )}
              </div>

              <div className="when__block">
                <h3 className="when__head">Final countdown</h3>
                <p className="faint">
                  {namedTrustees.length > 0
                    ? "Once the trustees agree"
                    : "Once the relay declares you silent"}
                  , your last chance to stop it — from any device, with your passphrase.
                </p>
                <Chips
                  label="Final countdown"
                  value={countdown}
                  onChange={setCountdown}
                  options={[
                    { value: 1, label: "1 day" },
                    { value: 3, label: "3 days", hint: "recommended" },
                    { value: 7, label: "1 week" },
                    { value: 14, label: "2 weeks" },
                  ]}
                />
              </div>
            </div>
          </section>
        )}

        {step === 3 && (
          <section className="wstep wstep--review">
            <h1 className="wstep__title serif">Read it once, out loud</h1>
            <blockquote className="sentence serif">{sentence}</blockquote>

            <dl className="review">
              <div>
                <dt>Holds</dt>
                <dd>
                  {api.plural(totalFiles, "item")} · {api.bytes(totalBytes)}
                </dd>
              </div>
              <div>
                <dt>For</dt>
                <dd>
                  {people
                    .map(
                      (p) =>
                        `${p.label.trim()}${p.backup ? " (backup)" : ""}${p.verified ? "" : " — key not verified"}`,
                    )
                    .join(", ")}
                </dd>
              </div>
              <div>
                <dt>Trustees</dt>
                <dd>
                  {namedTrustees.length
                    ? `${namedTrustees.join(", ")} — ${effectiveQuorum} must agree`
                    : "None — the relay alone decides"}
                </dd>
              </div>
            </dl>

            <div className="drills">
              {best && (
                <div className={`drill drill--${best.wouldRelease ? "good" : "bad"}`}>
                  <span className="drill__label">
                    {namedTrustees.length > 0 ? "If everyone answers" : "If you go silent"}
                  </span>
                  <span>{best.verdict}</span>
                </div>
              )}
              {likely && (
                <div className={`drill drill--${likely.wouldRelease ? "good" : "warn"}`}>
                  <span className="drill__label">
                    If only {Math.max(0, effectiveQuorum - 1)} answer
                  </span>
                  <span>{likely.verdict}</span>
                </div>
              )}
            </div>

            <div className="sealbar">
              {sealing ? (
                <div
                  className="progress"
                  role="progressbar"
                  aria-valuenow={Math.round((sealing.done / Math.max(1, sealing.total)) * 100)}
                >
                  <div
                    className="progress__fill"
                    style={{ width: `${(sealing.done / Math.max(1, sealing.total)) * 100}%` }}
                  />
                  <span className="progress__label">
                    Sealing… {api.bytes(sealing.done)} of {api.bytes(sealing.total)}
                  </span>
                </div>
              ) : (
                <HoldToConfirm label="Seal it" tone="neutral" onConfirm={() => void seal()} />
              )}
              <p className="faint">
                Hold to seal. Once sealed, the contents cannot be changed — only the people and the
                pieces.
              </p>
            </div>
          </section>
        )}

        {step === 4 && sealedId && (
          <section className="wstep">
            <h1 className="wstep__title serif">Sealed. Now hand out the pieces.</h1>
            {skipped.length > 0 && (
              <details className="skipped">
                <summary>
                  {api.plural(skipped.length, "thing was", "things were")} left out on purpose
                </summary>
                <ul>
                  {skipped.slice(0, 40).map((s) => (
                    <li key={s} className="mono">
                      {s}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <SharesPanel
              id={sealedId}
              onFinished={() => {
                onSealed();
                onClose();
              }}
            />
          </section>
        )}

        {error && step < 4 && (
          <p className="form-error wizard__error" role="alert">
            {error}
          </p>
        )}
      </main>

      {step < 3 && (
        <footer className="wizard__foot">
          <button
            type="button"
            className="btn btn--ghost"
            onClick={() => (step === 0 ? onClose() : setStep((s) => s - 1))}
          >
            {step === 0 ? "Cancel" : "Back"}
          </button>
          <button type="button" className="btn btn--primary btn--lg" onClick={next}>
            Continue
          </button>
        </footer>
      )}
      {step === 3 && !sealing && (
        <footer className="wizard__foot">
          <button type="button" className="btn btn--ghost" onClick={() => setStep(2)}>
            Back
          </button>
          <span />
        </footer>
      )}
    </div>
  );
}

function listOf(names: string[]): string {
  if (names.length <= 1) return names[0] ?? "them";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

function Timeline({
  interval,
  grace,
  silence,
  countdown,
  trustees,
}: {
  interval: number;
  grace: number;
  silence: number;
  countdown: number;
  trustees: number;
}) {
  const total = silence + countdown + 2;
  const at = (d: number) => `${(d / total) * 100}%`;
  return (
    <div className="ladder" aria-hidden="true">
      <div className="ladder__band ladder__band--calm" style={{ left: 0, width: at(interval) }} />
      <div
        className="ladder__band ladder__band--grace"
        style={{ left: at(interval), width: at(grace) }}
      />
      <div
        className="ladder__band ladder__band--remind"
        style={{ left: at(interval + grace), width: at(silence - interval - grace) }}
      />
      <div className="ladder__band ladder__band--ask" style={{ left: at(silence), width: at(2) }} />
      <div
        className="ladder__band ladder__band--count"
        style={{ left: at(silence + 2), width: at(countdown) }}
      />
      <span className="ladder__tick" style={{ left: at(interval) }}>
        day {interval}
        <em>check-in missed</em>
      </span>
      <span className="ladder__tick" style={{ left: at(interval + grace) }}>
        day {interval + grace}
        <em>reminders</em>
      </span>
      <span className="ladder__tick" style={{ left: at(silence) }}>
        day {silence}
        <em>{trustees > 0 ? "trustees asked" : "relay decides"}</em>
      </span>
      <span className="ladder__tick ladder__tick--end" style={{ left: "100%" }}>
        ~day {silence + 2 + countdown}
        <em>opens</em>
      </span>
    </div>
  );
}

function ImportEditor({
  onAdd,
  onCancel,
}: {
  onAdd: (s: ItemSpec) => Promise<string | null>;
  onCancel: () => void;
}) {
  const [path, setPath] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const isKeepass = path?.toLowerCase().endsWith(".kdbx") ?? false;
  const name = path?.split(/[\\/]/).pop();

  const choose = async () => {
    setProblem(null);
    try {
      const [first] = await api.pickPaths(false);
      if (first) setPath(first);
    } catch (e) {
      setProblem(say(e));
    }
  };

  return (
    <form
      className="secret"
      onSubmit={(e) => {
        e.preventDefault();
        if (!path) return;
        setProblem(null);
        void onAdd({ type: "import", path, password: isKeepass ? password : null }).then(
          setProblem,
        );
      }}
    >
      <p className="faint secret__hint">
        A KeePass database, a Bitwarden JSON export, a browser's exported passwords (CSV), or a .env
        file. Every entry becomes a small text file your recipient can open anywhere.
      </p>
      <div className="inline-field">
        <button type="button" className="btn btn--small" onClick={() => void choose()}>
          {path ? "Choose another file" : "Choose the export"}
        </button>
        {name && <span className="mono">{name}</span>}
      </div>
      {isKeepass && (
        <label className="field">
          <span className="field__label">Master password</span>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
            autoFocus
          />
        </label>
      )}
      {problem && (
        <p className="form-error" role="alert">
          {problem}
        </p>
      )}
      <div className="secret__actions">
        <button type="button" className="btn btn--ghost btn--small" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn btn--small" disabled={!path}>
          Add to capsule
        </button>
      </div>
    </form>
  );
}

function SecretEditor({
  kind,
  onAdd,
  onCancel,
}: {
  kind: SecretKind;
  onAdd: (s: ItemSpec) => Promise<string | null>;
  onCancel: () => void;
}) {
  const [problem, setProblem] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [text, setText] = useState("");
  const [user, setUser] = useState("");
  const [url, setUrl] = useState("");
  const first = useRef<HTMLInputElement>(null);
  useEffect(() => first.current?.focus(), [kind]);

  const spec = (): ItemSpec => {
    switch (kind) {
      case "note":
        return { type: "note", label, text };
      case "seed":
        return { type: "seedPhrase", label, words: text };
      case "totp":
        return { type: "totp", uri: text };
      case "codes":
        return { type: "recoveryCodes", label, text };
      case "login":
        return { type: "credential", label, username: user, password: text, url };
    }
  };

  const hints: Record<SecretKind, string> = {
    note: "Instructions, a letter, anything worth writing down.",
    seed: "12 or 24 words. The checksum is verified, so a typo is caught now rather than never.",
    totp: "The otpauth:// link behind a 2FA QR code — most authenticator apps can export it.",
    codes: "One code per line, as the service gave them to you.",
    login: "The password is sealed with everything else and never stored anywhere in the clear.",
  };

  return (
    <form
      className="secret"
      onSubmit={(e) => {
        e.preventDefault();
        setProblem(null);
        void onAdd(spec()).then(setProblem);
      }}
    >
      <p className="faint secret__hint">{hints[kind]}</p>
      {kind !== "totp" && (
        <label className="field">
          <span className="field__label">{kind === "login" ? "Site or service" : "Label"}</span>
          <input
            ref={first}
            className="input"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
        </label>
      )}
      {kind === "login" && (
        <>
          <label className="field">
            <span className="field__label">Web address</span>
            <input
              className="input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://"
            />
          </label>
          <label className="field">
            <span className="field__label">Username</span>
            <input
              className="input"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              autoComplete="off"
            />
          </label>
        </>
      )}
      <label className="field">
        <span className="field__label">
          {kind === "login"
            ? "Password"
            : kind === "totp"
              ? "otpauth:// link"
              : kind === "seed"
                ? "Words"
                : "Text"}
        </span>
        {kind === "login" || kind === "totp" ? (
          <input
            ref={kind === "totp" ? first : undefined}
            className="input mono"
            type={kind === "login" ? "password" : "text"}
            value={text}
            onChange={(e) => setText(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        ) : (
          <textarea
            className={`input ${kind === "seed" ? "mono" : ""}`}
            rows={kind === "note" ? 5 : 3}
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={kind === "note"}
          />
        )}
      </label>
      {problem && (
        <p className="form-error" role="alert">
          {problem}
        </p>
      )}
      <div className="secret__actions">
        <button type="button" className="btn btn--ghost btn--small" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn btn--small" disabled={!text.trim()}>
          Add to capsule
        </button>
      </div>
    </form>
  );
}
