import { useState } from "react";

import * as api from "../lib/api";
import type { Vigil } from "../lib/types";
import { HoldToConfirm } from "./HoldToConfirm";
import { Modal, Stepper } from "./ui";

const DAY = 86_400;

function days(secs: number): number {
  return Math.max(0, Math.round(secs / DAY));
}

function temper(v: Vigil): "calm" | "due" | "urgent" | "frozen" | "away" {
  if (v.frozenReason || v.stage === "frozen") return "frozen";
  if (v.holdUntil) return "away";
  if (v.stage === "countdown" || v.stage === "ready_to_release" || v.stage === "awaiting_quorum") {
    return "urgent";
  }
  if (v.dueInSecs <= 0 || v.stage === "grace" || v.stage === "escalating") return "due";
  return "calm";
}

interface Props {
  vigil: Vigil;
  onCheckIn: (underDuress: boolean) => void;
  checking: boolean;
  onHold: (days: number) => void;
  onEndHold: () => void;
  onAcknowledge: () => void;

  onRelay: () => void;
}

export function VigilBar({
  vigil,
  onCheckIn,
  checking,
  onHold,
  onEndHold,
  onAcknowledge,
  onRelay,
}: Props) {
  const mood = temper(vigil);
  const overdue = vigil.dueInSecs <= 0;
  const [away, setAway] = useState(false);
  const [awayDays, setAwayDays] = useState(14);

  const elapsed = Math.min(1, Math.max(0, vigil.silenceSecs / vigil.intervalSecs));
  const now = Date.now() / 1000;

  let headline: number;
  let caption: string;
  if (vigil.holdUntil) {
    headline = days(vigil.holdUntil - now);
    caption = headline === 1 ? "day left away" : "days left away";
  } else if (overdue) {
    headline = days(-vigil.dueInSecs);
    caption = headline === 1 ? "day past due" : "days past due";
  } else {
    headline = days(vigil.dueInSecs);
    caption = headline === 1 ? "day until your next check-in" : "days until your next check-in";
  }

  const relay = vigil.relay;

  return (
    <section className={`vigil vigil--${mood}`} aria-labelledby="vigil-rubric">
      <h2 className="rubric" id="vigil-rubric">
        The vigil
        <span className="rubric__count">check-in #{vigil.counter}</span>
      </h2>

      <div className="vigil__body">
        <div className="vigil__reading">
          <div className="vigil__number serif">{headline}</div>
          <div className="vigil__caption">{caption}</div>
          <div className="vigil__status">
            <span className="vigil__dot" aria-hidden="true" />
            {vigil.holdUntil ? `away until ${api.when(vigil.holdUntil)}` : vigil.summary}
            <span className="faint"> · quiet for {api.plural(days(vigil.silenceSecs), "day")}</span>
            <span className="vigil__relay faint">
              ·{" "}
              <button
                type="button"
                className="vigil__relaylink"
                onClick={onRelay}
                title="Relay settings"
              >
                {relay ? (
                  relay.lastError ? (
                    <span className="vigil__relay--bad">relay did not confirm</span>
                  ) : (
                    <>relay watching</>
                  )
                ) : (
                  <>no relay — local only</>
                )}
              </button>
            </span>
          </div>
        </div>

        <div className="vigil__action">
          <button
            type="button"
            className="here"
            onClick={(e) => onCheckIn(e.shiftKey)}
            disabled={checking}
            aria-describedby="here-hint"
          >
            <span className="here__glyph" aria-hidden="true" />
            {checking ? "Noted" : "I'm here"}
          </button>
          <p className="here__hint faint" id="here-hint">
            {vigil.holdUntil ? (
              <button type="button" className="linkbtn" onClick={onEndHold}>
                I'm back early
              </button>
            ) : (
              <>
                One click resets everything ·{" "}
                <button type="button" className="linkbtn" onClick={() => setAway(true)}>
                  I'll be away
                </button>
              </>
            )}
          </p>
        </div>
      </div>

      <div
        className={`trough ${overdue && !vigil.holdUntil ? "trough--overrun" : ""}`}
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(elapsed * 100)}
        aria-label="Time elapsed since your last check-in"
      >
        <div
          className="trough__ticks"
          aria-hidden="true"
          style={{ ["--ticks" as string]: Math.max(1, Math.round(vigil.intervalSecs / DAY)) }}
        />
        <div className="trough__fill" style={{ width: `${elapsed * 100}%` }} />
        <div className="trough__head" style={{ left: `${elapsed * 100}%` }} aria-hidden="true" />
      </div>

      {vigil.frozenReason && (
        <div className="vigil__frozen" role="alert">
          <p>
            <strong>The vigil is frozen.</strong> {vigil.frozenReason}. Nothing will advance toward
            release, and check-ins are paused, until you confirm the clock is right. If you did not
            change it, someone else did.
          </p>
          <HoldToConfirm
            label="The clock is right now"
            tone="neutral"
            holdMs={1500}
            onConfirm={onAcknowledge}
          />
        </div>
      )}

      {away && (
        <Modal title="Going away for a while?" kicker="Hold" onClose={() => setAway(false)}>
          <p className="gate__lead">
            Nothing moves while you are away — no reminders, no trustees asked. It ends by itself,
            and checking in ends it early. Holds are capped at {vigil.maxHoldDays} days: an endless
            hold would be a way to switch this off, including for someone who made you set one.
          </p>
          <div className="inline-field">
            <span>Away for</span>
            <Stepper
              label="days away"
              value={awayDays}
              min={1}
              max={vigil.maxHoldDays}
              onChange={setAwayDays}
              suffix="days"
            />
          </div>
          <div className="gate__actions">
            <button type="button" className="btn btn--ghost" onClick={() => setAway(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => {
                setAway(false);
                onHold(awayDays);
              }}
            >
              Hold for {api.plural(awayDays, "day")}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}
