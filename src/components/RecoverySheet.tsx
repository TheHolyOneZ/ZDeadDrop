import { useMemo, useState } from "react";

import * as api from "../lib/api";
import { Modal, Spinner, say } from "./ui";

function pickChecks(): number[] {
  const out: number[] = [];
  while (out.length < 3) {
    const n = Math.floor(Math.random() * 24);
    if (!out.some((m) => Math.abs(m - n) < 2)) out.push(n);
  }
  return out.sort((a, b) => a - b);
}

interface Props {
  inline?: boolean;
  onDone: () => void;
  onSkip: () => void;
}

export function RecoverySheet({ inline, onDone, onSkip }: Props) {
  const [stage, setStage] = useState<"explain" | "words" | "confirm" | "saving">("explain");
  const [words, setWords] = useState<string[]>([]);
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const [error, setError] = useState<string | null>(null);
  const checks = useMemo(pickChecks, [words]);

  const begin = async () => {
    setError(null);
    try {
      setWords(await api.beginRecoverySheet());
      setStage("words");
    } catch (e) {
      setError(say(e));
    }
  };

  const confirm = async () => {
    setStage("saving");
    setError(null);
    try {
      await api.confirmRecoverySheet(checks.map((i) => [i, answers[i] ?? ""]));
      setWords([]);
      onDone();
    } catch (e) {
      setError(say(e));
      setStage("confirm");
    }
  };

  const skip = () => {
    void api.cancelRecoverySheet();
    setWords([]);
    onSkip();
  };

  const body = (
    <div className="sheetflow">
      {stage === "explain" && (
        <>
          <p className="gate__lead">
            Twenty-four words, written on paper, that open this vault if you ever forget your
            passphrase. Without them, a forgotten passphrase means this vault is gone for good.
          </p>
          <ul className="sheetflow__rules">
            <li>
              Write them by hand, or print them. Never photograph them or paste them anywhere.
            </li>
            <li>Keep the paper somewhere you would keep a passport — a safe, or with your will.</li>
            <li>
              Anyone holding the sheet can open your vault. Guard it like the passphrase itself.
            </li>
          </ul>
          {error && <p className="form-error">{error}</p>}
          <div className="gate__actions">
            <button type="button" className="btn btn--ghost" onClick={skip}>
              Later
            </button>
            <button type="button" className="btn btn--primary btn--lg" onClick={() => void begin()}>
              Show me the words
            </button>
          </div>
        </>
      )}

      {stage === "words" && (
        <>
          <p className="gate__lead">Write these down, in order. They will not be shown again.</p>
          <ol className="words printable">
            {words.map((w, i) => (
              <li key={i}>
                <span className="words__n">{i + 1}</span>
                <span className="words__w">{w}</span>
              </li>
            ))}
          </ol>
          <div className="gate__actions">
            <button type="button" className="btn btn--ghost" onClick={() => window.print()}>
              Print
            </button>
            <button
              type="button"
              className="btn btn--primary btn--lg"
              onClick={() => setStage("confirm")}
            >
              I have written them down
            </button>
          </div>
        </>
      )}

      {(stage === "confirm" || stage === "saving") && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void confirm();
          }}
        >
          <p className="gate__lead">
            To be sure the sheet is right, type these three words from it.
          </p>
          <div className="sheetflow__checks">
            {checks.map((i, k) => (
              <label key={i} className="field">
                <span className="field__label">Word {i + 1}</span>
                <input
                  className="input input--lg mono"
                  value={answers[i] ?? ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, [i]: e.target.value }))}
                  autoFocus={k === 0}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={stage === "saving"}
                />
              </label>
            ))}
          </div>
          {error && <p className="form-error">{error}</p>}
          <div className="gate__actions">
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() => setStage("words")}
              disabled={stage === "saving"}
            >
              Show the words again
            </button>
            {stage === "saving" ? (
              <Spinner label="Adding the sheet to your vault" />
            ) : (
              <button type="submit" className="btn btn--primary btn--lg">
                Confirm
              </button>
            )}
          </div>
        </form>
      )}
    </div>
  );

  if (inline) {
    return (
      <div className="gate__form">
        <h1 className="gate__title serif">Your recovery sheet</h1>
        {body}
      </div>
    );
  }
  return (
    <Modal
      title="Your recovery sheet"
      kicker="Recovery"
      onClose={stage === "saving" ? undefined : skip}
    >
      {body}
    </Modal>
  );
}
