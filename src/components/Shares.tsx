import { useCallback, useEffect, useState } from "react";

import * as api from "../lib/api";
import type { ShareSlot, Shares } from "../lib/types";
import { CopyCode, Modal, Spinner, say, useToast } from "./ui";

export function SharesPanel({ id, onFinished }: { id: string; onFinished: () => void }) {
  const [shares, setShares] = useState<Shares | null | undefined>(undefined);
  const [confirmingEarly, setConfirmingEarly] = useState(false);
  const toast = useToast();

  const refresh = useCallback(() => {
    void api.pendingShares(id).then(setShares, () => setShares(null));
  }, [id]);
  useEffect(refresh, [refresh]);

  if (shares === undefined) return <Spinner label="Loading" />;
  if (shares === null) {
    return (
      <div className="shares">
        <p className="gate__lead">
          These shares have already been handed out and forgotten. If one was lost, issue a fresh
          set from the capsule — every old piece stops working.
        </p>
        <div className="gate__actions">
          <span />
          <button type="button" className="btn btn--primary" onClick={onFinished}>
            Close
          </button>
        </div>
      </div>
    );
  }

  const slots: ShareSlot[] = [...(shares.relay ? [shares.relay] : []), ...shares.trustees];
  const outstanding = slots.filter((s) => !s.handedOut).length;

  const save = async (which: string) => {
    try {
      if (await api.saveShare(id, which)) {
        toast("Saved. Hand it over, then delete any copy left on this machine.", "good");
        refresh();
      }
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const copy = async (which: string) => {
    try {
      await api.copyShare(id, which);
      toast("Copied. The clipboard clears itself in a minute.", "good");
      refresh();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const send = async () => {
    try {
      await api.sendRelayShare(id);
      toast("The relay has its piece. It hands it out only after you fall silent.", "good");
      refresh();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const finish = async () => {
    try {
      await api.finishShares(id);
      onFinished();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  return (
    <div className="shares">
      <p className="gate__lead">
        “{shares.capsule}” opens only when enough of these pieces come together. Give each one to
        the person named — on a USB stick, in person, or through a channel only they read. Nobody
        should hold more than one, and that includes you.
      </p>

      <ul className="shares__list">
        {slots.map((s) => (
          <li key={s.which} className="shares__row" data-done={s.handedOut}>
            <span className="shares__tick" aria-hidden="true">
              {s.handedOut ? "✓" : s.which === "relay" ? "⌁" : Number(s.which) + 1}
            </span>
            <span className="shares__who">
              <strong>{s.holder}</strong>
              <span className="faint">{s.which === "relay" ? "the relay's half" : "trustee"}</span>
            </span>
            {s.which === "relay" && shares.relayConnected ? (
              <button
                type="button"
                className="btn btn--small btn--primary"
                onClick={() => void send()}
              >
                Send to relay
              </button>
            ) : (
              <button type="button" className="btn btn--small" onClick={() => void save(s.which)}>
                Save to file
              </button>
            )}
            <button
              type="button"
              className="btn btn--small btn--ghost"
              onClick={() => void copy(s.which)}
            >
              Copy
            </button>
          </li>
        ))}
      </ul>

      <p className="shares__seal faint">
        Tell each of them the capsule's code, <CopyCode text={shares.seal} label="Seal code" />, so
        they know which capsule their piece belongs to.
      </p>

      <div className="gate__actions">
        <span className="faint">
          {outstanding === 0
            ? "Every piece has been handed out."
            : `${api.plural(outstanding, "piece")} still to hand out.`}
        </span>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => (outstanding > 0 ? setConfirmingEarly(true) : void finish())}
        >
          Done — forget them
        </button>
      </div>

      {confirmingEarly && (
        <Modal title="Forget the pieces now?" onClose={() => setConfirmingEarly(false)}>
          <p className="gate__lead">
            {api.plural(outstanding, "piece")} {outstanding === 1 ? "has" : "have"} not been handed
            out. Once forgotten they are gone, and if too few remain the capsule can never open. You
            can issue a fresh set later, which cancels every old piece.
          </p>
          <div className="gate__actions">
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() => setConfirmingEarly(false)}
            >
              Keep them for now
            </button>
            <button type="button" className="btn btn--danger" onClick={() => void finish()}>
              Forget them anyway
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
