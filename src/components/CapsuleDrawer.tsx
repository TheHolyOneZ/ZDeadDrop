import { useCallback, useEffect, useState } from "react";

import * as api from "../lib/api";
import type { CapsuleDetail, Recipient } from "../lib/types";
import { Seal } from "./Seal";
import { SharesPanel } from "./Shares";
import {
  CopyCode,
  Drawer,
  Stepper,
  Modal,
  Spinner,
  TypeAndHold,
  say,
  useContextMenu,
  useToast,
} from "./ui";

const STATE_WORDS: Record<string, string> = {
  sealed: "Sealed — you are checking in",
  stirring: "Stirring — a check-in is overdue",
  breaking: "Breaking — your trustees are being asked",
  broken: "Released",
  held: "Held",
  frozen: "Frozen — the clock cannot be trusted",
};

export function CapsuleDrawer({
  id,
  onClose,
  onChanged,
  initialAction,
}: {
  id: string;
  onClose: () => void;
  onChanged: () => void;

  initialAction?: "release" | "delete" | "reissue";
}) {
  const toast = useToast();
  const menu = useContextMenu();
  const [detail, setDetail] = useState<CapsuleDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showShares, setShowShares] = useState(false);
  const [danger, setDanger] = useState<"release" | "delete" | null>(
    initialAction === "release" || initialAction === "delete" ? initialAction : null,
  );
  const [busy, setBusy] = useState(false);
  const [replacing, setReplacing] = useState<Recipient | null>(null);
  const [confirmReissue, setConfirmReissue] = useState(initialAction === "reissue");
  const [editing, setEditing] = useState(false);

  const load = useCallback(() => {
    api.capsuleDetail(id).then(setDetail, (e) => setError(say(e)));
  }, [id]);
  useEffect(load, [load]);

  const changed = () => {
    load();
    onChanged();
  };

  if (error) {
    return (
      <Drawer onClose={onClose} label="Capsule">
        <p className="form-error">{error}</p>
      </Drawer>
    );
  }
  if (!detail) {
    return (
      <Drawer onClose={onClose} label="Capsule">
        <div className="drawer__loading">
          <Spinner label="Opening" />
        </div>
      </Drawer>
    );
  }

  const c = detail.capsule;
  const released = c.releasedAt !== null;

  const exportIt = async () => {
    try {
      const where = await api.exportCapsule(id);
      if (where) {
        toast("Exported. It is encrypted — safe to give them now.", "good");
        changed();
      }
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const verify = async (r: Recipient) => {
    try {
      await api.verifyRecipient(id, r.id);
      toast(`${r.label}'s key is marked as verified.`, "good");
      changed();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const reissue = async () => {
    try {
      await api.reissueShares(id);
      setShowShares(true);
      changed();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const release = async (typed: string) => {
    setBusy(true);
    try {
      const where = await api.releaseCapsule(id, typed);
      if (where) {
        toast("Released. Give the folder to them — it opens with their key alone.", "good");
        setDanger(null);
        changed();
      }
    } catch (e) {
      toast(say(e), "bad");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (typed: string) => {
    setBusy(true);
    try {
      await api.deleteCapsule(id, typed);
      toast(`“${c.name}” was deleted.`, "good");
      onChanged();
      onClose();
    } catch (e) {
      toast(say(e), "bad");
      setBusy(false);
    }
  };

  const tiers = [...new Set(detail.recipients.map((r) => r.tier))].sort();

  return (
    <Drawer onClose={onClose} label={c.name}>
      <div className="dossier">
        <header className="dossier__head">
          <div className="dossier__seal">
            <Seal seed={c.sealSeed} state={c.state} size={148} />
          </div>
          <div className="dossier__title">
            <p className={`dossier__state dossier__state--${c.state}`}>
              <span className={`capsule__pip capsule__pip--${c.state}`} aria-hidden="true" />
              {STATE_WORDS[c.state] ?? c.state}
            </p>
            <h2 className="serif">{c.name}</h2>
            <p className="dossier__code">
              <CopyCode text={c.fingerprint} label="Seal code" />
            </p>
            <p className="dossier__figure faint">{c.figure}</p>
          </div>
        </header>

        <div className="dossier__conditionrow">
          <p className="dossier__condition">{c.condition}.</p>
          {!released && (
            <button type="button" className="linkbtn" onClick={() => setEditing(true)}>
              Change…
            </button>
          )}
        </div>
        {detail.policyWeakness && <p className="warnline">{detail.policyWeakness}</p>}
        {detail.note && <blockquote className="dossier__note serif">“{detail.note}”</blockquote>}

        {!released && (
          <div className="dossier__actions">
            <button type="button" className="btn" onClick={() => void exportIt()}>
              Export for{" "}
              {detail.recipients.length === 1 ? detail.recipients[0]!.label : "recipients"}
            </button>
            {c.sharesPending ? (
              <button
                type="button"
                className="btn btn--primary"
                onClick={() => setShowShares(true)}
              >
                Hand out the pieces
              </button>
            ) : (
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => setConfirmReissue(true)}
              >
                Issue new pieces
              </button>
            )}
          </div>
        )}
        {!released && (
          <p className="faint dossier__exported">
            {c.exportedAt
              ? `Last exported ${api.when(c.exportedAt)}.`
              : "Never exported — it exists only on this machine."}
          </p>
        )}

        <section className="dossier__section">
          <h3 className="rubric">
            Goes to{" "}
            <span className="rubric__count">
              {api.plural(detail.recipients.length, "person", "people")}
            </span>
          </h3>
          {tiers.map((tier) => (
            <div key={tier} className="tier">
              {tiers.length > 1 && (
                <p className="tier__label faint">
                  {tier === 0 ? "First in line" : `Backup — if nobody above claims it in time`}
                </p>
              )}
              {detail.recipients
                .filter((r) => r.tier === tier)
                .map((r) => (
                  <div
                    key={r.id}
                    className="recipient"
                    onContextMenu={(e) =>
                      menu(e, [
                        {
                          label: "Copy key code",
                          onSelect: () =>
                            void api.copyText(r.fingerprint).then(
                              () => toast(`Key code copied: ${r.fingerprint}`, "good"),
                              (err) => toast(say(err), "bad"),
                            ),
                        },
                        {
                          label: r.verifiedAt ? "Verified already" : "It matched — mark verified",
                          disabled: r.verifiedAt !== null,
                          onSelect: () => void verify(r),
                        },
                        {
                          label: "Replace key…",
                          disabled: released,
                          onSelect: () => setReplacing(r),
                        },
                      ])
                    }
                  >
                    <Seal seed={r.sealSeed} state="sealed" size={52} simplified />
                    <div className="recipient__text">
                      <strong>{r.label}</strong>
                      <CopyCode text={r.fingerprint} label="Key code" />
                      <span className="faint recipient__figure">{r.figure}</span>
                    </div>
                    <div className="recipient__actions">
                      {r.verifiedAt ? (
                        <span className="badge badge--good">verified {api.when(r.verifiedAt)}</span>
                      ) : (
                        <button
                          type="button"
                          className="btn btn--small"
                          onClick={() => void verify(r)}
                          title="Read the code to them over a channel you trust. If it matches, mark it."
                        >
                          It matched — verify
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn--small btn--ghost"
                        onClick={() => setReplacing(r)}
                        disabled={released}
                      >
                        Replace key
                      </button>
                    </div>
                  </div>
                ))}
            </div>
          ))}
        </section>

        {detail.trustees.length > 0 && (
          <section className="dossier__section">
            <h3 className="rubric">
              Trustees{" "}
              <span className="rubric__count">
                {c.quorum ? `${c.quorum.need} of ${c.quorum.of} must agree` : ""}
              </span>
            </h3>
            <ul className="trusteelist">
              {detail.trustees.map((t, i) => (
                <li key={i}>
                  <span className="trustees__n">{i + 1}</span>
                  {t}
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="dossier__section">
          <h3 className="rubric">
            Inside{" "}
            <span className="rubric__count">
              {api.plural(detail.entries.length, "item")} · {api.bytes(c.sizeBytes)}
            </span>
          </h3>
          <ul className="manifest">
            {detail.entries.slice(0, 200).map((e) => (
              <li key={e.path}>
                <span className="manifest__path selectable">{e.path}</span>
                <span className="faint">
                  {e.kind === "file" ? api.bytes(e.size) : e.kind.replace(/_/g, " ")}
                </span>
              </li>
            ))}
            {detail.entries.length > 200 && (
              <li className="faint">…and {detail.entries.length - 200} more</li>
            )}
          </ul>
        </section>

        {!released && (
          <section className="dossier__section dossier__grave">
            <h3 className="rubric">If this is the day</h3>
            <p className="faint">
              Releasing now writes a copy that opens with the recipient's key alone — no silence, no
              trustees, no countdown. Deleting removes it from this vault; any copy already exported
              is unaffected.
            </p>
            <div className="dossier__actions">
              <button
                type="button"
                className="btn btn--danger-ghost"
                onClick={() => setDanger("release")}
              >
                Release now…
              </button>
              <button
                type="button"
                className="btn btn--danger-ghost"
                onClick={() => setDanger("delete")}
              >
                Delete…
              </button>
            </div>
          </section>
        )}
        {released && (
          <section className="dossier__section">
            <p className="faint">
              Released {api.when(c.releasedAt)}. It can be deleted from this vault once they have
              it.
            </p>
            <button
              type="button"
              className="btn btn--danger-ghost"
              onClick={() => setDanger("delete")}
            >
              Delete…
            </button>
          </section>
        )}
      </div>

      {confirmReissue && (
        <Modal
          title="Issue a new set of pieces?"
          kicker={c.name}
          onClose={() => setConfirmReissue(false)}
        >
          <p className="gate__lead">
            For a lost piece, a trustee who has died, or pieces that were never handed out. Three
            things follow:
          </p>
          <ul className="sheetflow__rules">
            <li>Every piece handed out before stops working. Each trustee needs their new one.</li>
            <li>
              The capsule gets a new seal, because the seal covers its gate. Tell the recipients the
              new code.
            </li>
            <li>Any copy you exported before will not open. Export it again afterwards.</li>
          </ul>
          <div className="gate__actions">
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() => setConfirmReissue(false)}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => {
                setConfirmReissue(false);
                void reissue();
              }}
            >
              Issue new pieces
            </button>
          </div>
        </Modal>
      )}

      {showShares && (
        <Modal
          title="Hand out the pieces"
          kicker={c.name}
          onClose={() => setShowShares(false)}
          wide
        >
          <SharesPanel
            id={id}
            onFinished={() => {
              setShowShares(false);
              changed();
            }}
          />
        </Modal>
      )}

      {danger && (
        <Modal
          title={danger === "release" ? `Release “${c.name}” now?` : `Delete “${c.name}”?`}
          kicker="Cannot be undone"
          onClose={busy ? undefined : () => setDanger(null)}
        >
          <p className="gate__lead">
            {danger === "release"
              ? "You will choose a folder. What is written there opens with the recipient's key alone — there is no way to call it back once it has left this machine."
              : "The capsule and its contents are removed from this vault. Trustees' pieces become useless. Exported copies are not affected."}
          </p>
          <TypeAndHold
            name={c.name}
            action={danger === "release" ? "Release it" : "Delete it"}
            busy={busy}
            onConfirm={(typed) => void (danger === "release" ? release(typed) : remove(typed))}
          />
        </Modal>
      )}

      {editing && (
        <TermsEditor
          id={id}
          detail={detail}
          onClose={() => setEditing(false)}
          onSaved={(newPieces) => {
            setEditing(false);
            changed();
            if (newPieces) setShowShares(true);
            toast(
              newPieces
                ? "Conditions changed. Hand out the new pieces — the old ones no longer work."
                : "Conditions changed.",
              "good",
            );
          }}
        />
      )}

      {replacing && (
        <ReplaceKey
          capsule={id}
          recipient={replacing}
          onClose={() => setReplacing(null)}
          onDone={() => {
            setReplacing(null);
            toast(`${replacing.label}'s key was replaced. Verify the new one with them.`, "good");
            changed();
          }}
        />
      )}
    </Drawer>
  );
}

function TermsEditor({
  id,
  detail,
  onClose,
  onSaved,
}: {
  id: string;
  detail: CapsuleDetail;
  onClose: () => void;
  onSaved: (newPieces: boolean) => void;
}) {
  const [silence, setSilence] = useState(detail.silenceDays);
  const [countdown, setCountdown] = useState(detail.countdownDays);
  const [trustees, setTrustees] = useState(
    detail.trustees.map((name, i) => ({ name, contact: detail.trusteeContacts[i] ?? "" })),
  );
  const [quorum, setQuorum] = useState(detail.capsule.quorum?.need ?? 2);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const names = trustees.map((t) => t.name.trim());
  const gateChanges =
    names.join("\u0000") !== detail.trustees.join("\u0000") ||
    (trustees.length >= 2 ? Math.min(quorum, trustees.length) : 0) !==
      (detail.capsule.quorum?.need ?? 0);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const pieces = await api.updateTerms(
        id,
        silence,
        countdown,
        trustees.map((t) => ({ name: t.name.trim(), contact: t.contact.trim() || null })),
        Math.min(quorum, trustees.length),
      );
      onSaved(pieces);
    } catch (e) {
      setError(say(e));
      setBusy(false);
    }
  };

  return (
    <Modal title="Change the conditions" kicker={detail.capsule.name} onClose={onClose} wide>
      <div className="settings__grid">
        <span>Silence before trustees are asked</span>
        <Stepper
          label="days of silence"
          value={silence}
          min={2}
          max={365}
          onChange={setSilence}
          suffix="days"
        />
        <span>Final countdown</span>
        <Stepper
          label="countdown days"
          value={countdown}
          min={1}
          max={90}
          onChange={setCountdown}
          suffix="days"
        />
      </div>

      <h3 className="rubric">Trustees</h3>
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
              onClick={() => setTrustees((ts) => ts.filter((_, j) => j !== i))}
            >
              ×
            </button>
          </li>
        ))}
      </ul>
      <div className="wstep__row">
        <button
          type="button"
          className="btn btn--small btn--ghost"
          onClick={() => setTrustees((ts) => [...ts, { name: "", contact: "" }])}
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
        <p className="warnline">No trustees: whoever runs the relay could open this alone.</p>
      )}
      {gateChanges && (
        <p className="warnline">
          Changing who the trustees are, or how many must agree, issues new pieces. Every old piece
          stops working, the capsule's seal changes, and any copy you exported must be exported
          again.
        </p>
      )}
      {error && <p className="form-error">{error}</p>}
      <div className="gate__actions">
        <button type="button" className="btn btn--ghost" onClick={onClose} disabled={busy}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => void save()}
          disabled={busy}
        >
          {busy ? <Spinner label="Saving" /> : gateChanges ? "Save and issue new pieces" : "Save"}
        </button>
      </div>
    </Modal>
  );
}

function ReplaceKey({
  capsule,
  recipient,
  onClose,
  onDone,
}: {
  capsule: string;
  recipient: Recipient;
  onClose: () => void;
  onDone: () => void;
}) {
  const [text, setText] = useState("");
  const [key, setKey] = useState<Awaited<ReturnType<typeof api.inspectKey>> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const read = async (t: string) => {
    setText(t);
    setKey(null);
    setError(null);
    if (!t.trim()) return;
    try {
      setKey(await api.inspectKey(t));
    } catch (e) {
      setError(say(e));
    }
  };

  const apply = async () => {
    try {
      await api.replaceRecipientKey(capsule, recipient.id, text);
      onDone();
    } catch (e) {
      setError(say(e));
    }
  };

  return (
    <Modal title={`A new key for ${recipient.label}`} kicker="Replace key" onClose={onClose}>
      <p className="gate__lead">
        For when their old key was lost. Only the wrapped key changes — the contents are not
        re-sealed, and the old key stops working for this capsule. The capsule's seal changes too,
        and any copy exported before will not open: export it again afterwards.
      </p>
      <label className="field">
        <span className="field__label">Their new public key</span>
        <textarea
          className="input mono"
          rows={2}
          value={text}
          onChange={(e) => void read(e.target.value)}
          spellCheck={false}
        />
      </label>
      {key && (
        <div className="keypreview">
          <Seal seed={key.sealSeed} state="sealed" size={64} simplified />
          <div>
            <CopyCode text={key.fingerprint} label="Key code" />
            <p className="faint">{key.figure}</p>
          </div>
        </div>
      )}
      {error && <p className="form-error">{error}</p>}
      <div className="gate__actions">
        <button type="button" className="btn btn--ghost" onClick={onClose}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn--primary"
          disabled={!key}
          onClick={() => void apply()}
        >
          Replace
        </button>
      </div>
    </Modal>
  );
}
