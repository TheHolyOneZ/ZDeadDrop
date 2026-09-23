import { useEffect, useRef, useState } from "react";

import logo from "../assets/logo.png";
import * as api from "../lib/api";
import type { Status } from "../lib/types";
import { RecoverySheet } from "./RecoverySheet";
import { Seal } from "./Seal";
import { Chips, CopyCode, Spinner, say } from "./ui";

function strength(p: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
  if (p.length === 0) return { score: 0, label: "" };
  const words = p
    .trim()
    .split(/\s+/)
    .filter((w) => w.length >= 3);
  let bits: number;
  if (words.length >= 3) {
    bits = words.length * 11;
  } else {
    let pool = 0;
    if (/[a-z]/.test(p)) pool += 26;
    if (/[A-Z]/.test(p)) pool += 26;
    if (/[0-9]/.test(p)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(p)) pool += 20;

    bits = (p.length * Math.log2(Math.max(pool, 2))) / 2;
  }
  if (/^(.)\1+$/.test(p) || /password|123456|qwerty/i.test(p)) bits = Math.min(bits, 10);
  if (p.length < 10) return { score: 1, label: "Too short" };
  if (bits < 36) return { score: 1, label: "Weak — easy to guess" };
  if (bits < 48) return { score: 2, label: "Fair" };
  if (bits < 64) return { score: 3, label: "Strong" };
  return { score: 4, label: "Excellent" };
}

type Step = "welcome" | "passphrase" | "creating" | "sheet" | "schedule";

export function Onboarding({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<Step>("welcome");
  const [pass, setPass] = useState("");
  const [again, setAgain] = useState("");
  const [reveal, setReveal] = useState(false);
  const [preset, setPreset] = useState<"interactive" | "moderate" | "paranoid">("moderate");
  const [unrecoverable, setUnrecoverable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cadence, setCadence] = useState(30);
  const s = strength(pass);

  const create = async () => {
    setError(null);
    if (pass !== again) return setError("The two passphrases do not match.");
    if (s.score < 2)
      return setError("Choose something harder to guess. Four or five unrelated words works well.");
    setStep("creating");
    try {
      await api.createVault(pass, preset, unrecoverable);
      setPass("");
      setAgain("");
      setStep(unrecoverable ? "schedule" : "sheet");
    } catch (e) {
      setError(say(e));
      setStep("passphrase");
    }
  };

  const finish = async () => {
    try {
      await api.savePrefs(cadence, 7, 10);
    } catch {}
    onDone();
  };

  return (
    <div className="gate grain">
      <div className="gate__panel gate__panel--wide">
        <ol className="gate__steps" aria-label="Setting up">
          {(["welcome", "passphrase", "sheet", "schedule"] as const).map((k, i) => {
            const at =
              step === "creating"
                ? 1
                : ["welcome", "passphrase", "sheet", "schedule"].indexOf(step);
            return (
              <li key={k} data-on={i === at} data-done={i < at}>
                {["Welcome", "Passphrase", "Recovery", "Rhythm"][i]}
              </li>
            );
          })}
        </ol>

        {step === "welcome" && (
          <div className="welcome">
            <div className="welcome__seal">
              <img src={logo} alt="ZDeadDrop" width={220} height={220} />
            </div>
            <div className="welcome__copy">
              <span className="welcome__by">ZDeadDrop · by TheHolyOneZ</span>
              <h1 className="welcome__title serif">
                If you go silent, the right things reach the right people.
              </h1>
              <p className="welcome__lead">
                ZDeadDrop seals files and secrets for the people you choose. While you check in,
                nothing happens. If you stop, reminders go out, your trustees are asked, and only
                then — after a last countdown — does anything open. And only for them.
              </p>
              <ul className="welcome__points">
                <li>
                  <strong>Nothing leaves this machine unencrypted.</strong> Not to a relay, not to a
                  trustee, not to us.
                </li>
                <li>
                  <strong>No single person can open anything early</strong> — not a trustee, not the
                  relay, not someone who steals this laptop.
                </li>
                <li>
                  <strong>It is not a will.</strong> It hands over data, not legal ownership. It
                  cannot know that you have died; it can only notice that you have gone quiet.
                </li>
              </ul>
              <button
                type="button"
                className="btn btn--primary btn--lg"
                onClick={() => setStep("passphrase")}
              >
                Begin
              </button>
            </div>
          </div>
        )}

        {(step === "passphrase" || step === "creating") && (
          <form
            className="gate__form"
            onSubmit={(e) => {
              e.preventDefault();
              void create();
            }}
          >
            <h1 className="gate__title serif">Choose a passphrase</h1>
            <p className="gate__lead">
              It protects everything you put in here. Long and memorable beats short and clever:
              four or five unrelated words, like <em>lantern orbit velvet thistle</em>. Nobody —
              including us — can reset it.
            </p>

            <label className="field">
              <span className="field__label">Passphrase</span>
              <div className="input-reveal">
                <input
                  className="input input--lg"
                  type={reveal ? "text" : "password"}
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  autoFocus
                  autoComplete="new-password"
                  spellCheck={false}
                  disabled={step === "creating"}
                />
                <button
                  type="button"
                  className="input-reveal__btn"
                  onClick={() => setReveal((r) => !r)}
                >
                  {reveal ? "Hide" : "Show"}
                </button>
              </div>
              <div className="meter" data-score={s.score} aria-live="polite">
                <span />
                <span />
                <span />
                <span />
                <em>{s.label}</em>
              </div>
            </label>

            <label className="field">
              <span className="field__label">Once more</span>
              <input
                className="input input--lg"
                type={reveal ? "text" : "password"}
                value={again}
                onChange={(e) => setAgain(e.target.value)}
                autoComplete="new-password"
                spellCheck={false}
                disabled={step === "creating"}
              />
            </label>

            <div className="field">
              <span className="field__label">How hard should it be to attack?</span>
              <Chips
                label="Key strength"
                value={preset}
                onChange={setPreset}
                options={[
                  { value: "interactive", label: "Quick", hint: "about a second to unlock" },
                  { value: "moderate", label: "Balanced", hint: "a few seconds · recommended" },
                  { value: "paranoid", label: "Fortress", hint: "slow to unlock, 1 GB of memory" },
                ]}
              />
            </div>

            <label className="check">
              <input
                type="checkbox"
                checked={unrecoverable}
                onChange={(e) => setUnrecoverable(e.target.checked)}
                disabled={step === "creating"}
              />
              <span>
                <strong>No way back in, ever.</strong> Refuse every recovery method, permanently. If
                you forget the passphrase you will never open this vault again — though your
                capsules still reach their recipients on schedule.
              </span>
            </label>

            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}

            <div className="gate__actions">
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => setStep("welcome")}
                disabled={step === "creating"}
              >
                Back
              </button>
              {step === "creating" ? (
                <Spinner label="Deriving your keys — this takes a few seconds on purpose" />
              ) : (
                <button
                  type="submit"
                  className="btn btn--primary btn--lg"
                  disabled={!pass || !again}
                >
                  Create the vault
                </button>
              )}
            </div>
          </form>
        )}

        {step === "sheet" && (
          <RecoverySheet
            inline
            onDone={() => setStep("schedule")}
            onSkip={() => setStep("schedule")}
          />
        )}

        {step === "schedule" && (
          <div className="gate__form">
            <h1 className="gate__title serif">How often will you check in?</h1>
            <p className="gate__lead">
              A check-in is one click on “I'm here”. Pick a rhythm you will actually keep — the
              right answer depends on your life, not on ours. You can change it later.
            </p>
            <Chips
              label="Check-in interval"
              value={cadence}
              onChange={setCadence}
              options={[
                { value: 7, label: "Weekly", hint: "for a switch that should act fast" },
                { value: 14, label: "Fortnightly" },
                { value: 30, label: "Monthly", hint: "recommended" },
                { value: 90, label: "Quarterly", hint: "for people who travel" },
              ]}
            />
            <p className="gate__note">
              Missing one check-in never releases anything. After it, you get a week of grace, then
              reminders, then your trustees are asked — and only if enough of them agree does a
              final countdown begin, which you can still stop.
            </p>
            <div className="gate__actions">
              <span />
              <button
                type="button"
                className="btn btn--primary btn--lg"
                onClick={() => void finish()}
              >
                Open the vault
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function LockScreen({ status, onUnlocked }: { status: Status; onUnlocked: () => void }) {
  const [mode, setMode] = useState<"pass" | "sheet">("pass");
  const [pass, setPass] = useState("");
  const [words, setWords] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (mode === "pass") input.current?.focus();
  }, [mode]);

  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      if (mode === "pass") await api.unlock(pass);
      else await api.unlockWithSheet(words);
      setPass("");
      setWords("");
      onUnlocked();
    } catch (e) {
      setError(say(e));
      setShake((n) => n + 1);
      setBusy(false);
      window.setTimeout(() => input.current?.select(), 0);
    }
  };

  return (
    <div className="gate grain">
      <form
        className="gate__panel lock"
        onSubmit={(e) => {
          e.preventDefault();
          void go();
        }}
      >
        <div className="lock__seal" key={shake} data-shake={shake > 0}>
          {status.sealSeed && <Seal seed={status.sealSeed} state="sealed" size={168} />}
        </div>
        <p className="lock__vault">
          {status.shortId && <CopyCode text={status.shortId} label="Vault code" />}
        </p>
        <h1 className="lock__title serif">The vault is locked</h1>
        <p className="lock__by">ZDeadDrop · by TheHolyOneZ</p>

        {mode === "pass" ? (
          <input
            ref={input}
            className="input input--lg lock__input"
            type="password"
            placeholder="Passphrase"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            disabled={busy}
            autoComplete="current-password"
            aria-label="Passphrase"
          />
        ) : (
          <textarea
            className="input lock__words"
            placeholder="The 24 words from your recovery sheet, in order"
            value={words}
            onChange={(e) => setWords(e.target.value)}
            disabled={busy}
            rows={4}
            spellCheck={false}
            aria-label="Recovery sheet words"
          />
        )}

        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}

        <button
          type="submit"
          className="btn btn--primary btn--lg lock__go"
          disabled={busy || (mode === "pass" ? !pass : !words.trim())}
        >
          {busy ? <Spinner label="Opening" /> : "Unlock"}
        </button>

        {status.recoveryPolicy === "standard" && (
          <button
            type="button"
            className="linkbtn"
            onClick={() => {
              setMode(mode === "pass" ? "sheet" : "pass");
              setError(null);
            }}
          >
            {mode === "pass" ? "Forgot it? Use your recovery sheet" : "Use your passphrase instead"}
          </button>
        )}

        <p className="lock__footnote faint">
          Locking never changes what happens to your capsules. It only keeps this window, and the
          keys behind it, out of reach.
        </p>
      </form>
    </div>
  );
}
