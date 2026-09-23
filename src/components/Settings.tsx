import { useState } from "react";

import * as api from "../lib/api";
import type { VaultSummary, Vigil } from "../lib/types";
import { Seal } from "./Seal";
import { CopyCode, Drawer, Spinner, Stepper, say, useToast } from "./ui";

export function Settings({
  vault,
  vigil,
  onClose,
  onChanged,
  onRecoverySheet,
  onAbout,
}: {
  vault: VaultSummary;
  vigil: Vigil | null;
  onClose: () => void;
  onChanged: () => void;
  onRecoverySheet: () => void;
  onAbout: () => void;
}) {
  const toast = useToast();
  const [interval, setIntervalDays] = useState(vault.checkinIntervalDays);
  const [grace, setGrace] = useState(vault.graceDays);
  const [autoLock, setAutoLock] = useState(vault.autoLockMinutes);
  const [relayUrl, setRelayUrl] = useState(vault.relayUrl ?? "");
  const [contact, setContact] = useState(vault.ownerContact ?? "");
  const [connecting, setConnecting] = useState(false);

  const dirty =
    interval !== vault.checkinIntervalDays ||
    grace !== vault.graceDays ||
    autoLock !== vault.autoLockMinutes;

  const save = async () => {
    try {
      await api.savePrefs(interval, grace, autoLock);
      toast("Saved.", "good");
      onChanged();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const connect = async () => {
    setConnecting(true);
    try {
      await api.connectRelay(relayUrl, contact || null);
      toast("Connected. Your first check-in was received and its receipt verified.", "good");
      onChanged();
    } catch (e) {
      toast(say(e), "bad");
    } finally {
      setConnecting(false);
    }
  };

  const disconnect = async () => {
    try {
      await api.disconnectRelay();
      setRelayUrl("");
      toast("Disconnected. Nothing will remind you now.", "plain");
      onChanged();
    } catch (e) {
      toast(say(e), "bad");
    }
  };

  const relay = vigil?.relay ?? null;

  return (
    <Drawer onClose={onClose} label="Settings">
      <div className="dossier settings">
        <header className="settings__head">
          <Seal seed={vault.vigilSeed} state="sealed" size={72} simplified />
          <div>
            <h2 className="serif">This vault</h2>
            <p>
              <CopyCode text={vault.shortId} label="Vault code" />
            </p>
            <p className="faint">
              Signing identity <CopyCode text={vault.vigilFingerprint} label="Signing identity" />
            </p>
          </div>
        </header>

        <section className="dossier__section">
          <h3 className="rubric">Rhythm</h3>
          <div className="settings__grid">
            <span>Check in every</span>
            <Stepper
              label="days between check-ins"
              value={interval}
              min={1}
              max={365}
              onChange={setIntervalDays}
              suffix="days"
            />
            <span>Then a grace period of</span>
            <Stepper
              label="grace days"
              value={grace}
              min={0}
              max={60}
              onChange={setGrace}
              suffix="days"
            />
            <span>Lock this window after</span>
            <Stepper
              label="minutes idle"
              value={autoLock}
              min={1}
              max={240}
              onChange={setAutoLock}
              suffix="min idle"
            />
          </div>
          <div className="settings__save">
            <button
              type="button"
              className="btn btn--primary btn--small"
              disabled={!dirty}
              onClick={() => void save()}
            >
              Save
            </button>
          </div>
        </section>

        <section className="dossier__section">
          <h3 className="rubric">Relay</h3>
          <p className="faint">
            A relay notices when you go quiet, sends your reminders, and holds half of each release
            key. It never sees what is inside, cannot forge a check-in, and cannot hide one without
            being caught. Run your own with Docker, or use one a friend runs.
          </p>
          {relay ? (
            <div className="relaystate">
              <p>
                <span
                  className={`dot dot--${relay.lastError ? "bad" : "good"}`}
                  aria-hidden="true"
                />
                <CopyCode text={relay.url} label="Relay address" />
              </p>
              <p className="faint">
                {relay.lastError
                  ? relay.lastError
                  : relay.lastReceiptAt
                    ? `Last check-in confirmed ${api.when(relay.lastReceiptAt)}, receipt verified.`
                    : "Connected."}
              </p>
              <button
                type="button"
                className="btn btn--small btn--ghost"
                onClick={() => void disconnect()}
              >
                Disconnect
              </button>
            </div>
          ) : (
            <form
              className="settings__relay"
              onSubmit={(e) => {
                e.preventDefault();
                void connect();
              }}
            >
              <label className="field">
                <span className="field__label">Relay address</span>
                <input
                  className="input mono"
                  value={relayUrl}
                  onChange={(e) => setRelayUrl(e.target.value)}
                  placeholder="https://relay.example.org"
                />
              </label>
              <label className="field">
                <span className="field__label">Where to remind you</span>
                <input
                  className="input"
                  value={contact}
                  onChange={(e) => setContact(e.target.value)}
                  placeholder="mailto:you@example.org  or  https://ntfy.sh/your-topic"
                />
                <span className="field__hint">
                  An email address, or a webhook such as ntfy. Two channels are safer than one.
                </span>
              </label>
              <button
                type="submit"
                className="btn btn--small"
                disabled={!relayUrl.trim() || connecting}
              >
                {connecting ? <Spinner label="Connecting" /> : "Connect"}
              </button>
            </form>
          )}
        </section>

        <section className="dossier__section">
          <h3 className="rubric">If you forget your passphrase</h3>
          {vault.recoveryPolicy === "unrecoverable" ? (
            <p className="faint">
              This vault was made without recovery, by choice, and that cannot be changed. Your
              capsules still reach their recipients on schedule if you forget it.
            </p>
          ) : vault.recoverySheetAt ? (
            <p>
              <span className="badge badge--good">
                recovery sheet since {api.when(vault.recoverySheetAt)}
              </span>
            </p>
          ) : (
            <>
              <p className="faint">
                You have no recovery sheet. A forgotten passphrase would mean this vault is gone for
                good.
              </p>
              <button
                type="button"
                className="btn btn--primary btn--small"
                onClick={onRecoverySheet}
              >
                Make a recovery sheet
              </button>
            </>
          )}
        </section>

        <section className="dossier__section">
          <h3 className="rubric">If someone forces you</h3>
          <p className="faint">
            Hold <kbd>Shift</kbd> while pressing <em>I'm here</em>. The check-in looks and behaves
            exactly like any other — on this screen, at the relay, everywhere — but carries a sealed
            flag only your trustees can read, telling them not to believe it.
          </p>
        </section>

        <section className="dossier__section">
          <h3 className="rubric">Where it lives</h3>
          <p className="settings__path">
            <CopyCode text={vault.path} label="Vault folder" />
          </p>
          <button
            type="button"
            className="btn btn--small btn--ghost"
            onClick={() => void api.revealVault().catch((e) => toast(say(e), "bad"))}
          >
            Show in file manager
          </button>
          <p className="faint">
            Everything in that folder is encrypted. Back it up anywhere; without your passphrase or
            recovery sheet it is noise.
          </p>
        </section>
        <section className="dossier__section">
          <button
            type="button"
            className="btn btn--ghost btn--small settings__about"
            onClick={onAbout}
          >
            About ZDeadDrop
          </button>
        </section>
      </div>
    </Drawer>
  );
}
