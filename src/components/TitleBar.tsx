import logo from "../assets/logo.png";
import { inTauri } from "../lib/api";
import { CopyCode } from "./ui";
import type { VaultSummary } from "../lib/types";

async function windowAction(action: "minimise" | "maximise" | "close") {
  if (!inTauri()) return;
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  const win = getCurrentWindow();
  if (action === "minimise") await win.minimize();
  else if (action === "maximise") await win.toggleMaximize();
  else await win.close();
}

interface Props {
  vault: VaultSummary | null;
  theme: "ink" | "parchment";
  onToggleTheme: () => void;

  onLock?: () => void;
  onSettings?: () => void;
  onAbout: () => void;
}

export function TitleBar({ vault, theme, onToggleTheme, onLock, onSettings, onAbout }: Props) {
  return (
    <header className="titlebar" data-tauri-drag-region>
      <button
        type="button"
        className="titlebar__mark"
        onClick={onAbout}
        title="About ZDeadDrop"
        aria-label="About ZDeadDrop"
      >
        <img className="titlebar__logo" src={logo} alt="" width={20} height={20} />
        <span className="titlebar__name serif">ZDeadDrop</span>
        <span className="titlebar__by">by TheHolyOneZ</span>
      </button>

      <div className="titlebar__vault">
        {vault && (
          <>
            <CopyCode text={vault.shortId} label="Vault code" />
            <span className="titlebar__sep" aria-hidden="true">
              ·
            </span>
            <span className="faint">
              {vault.trusteeCount} {vault.trusteeCount === 1 ? "trustee" : "trustees"} ·{" "}
              {vault.relayUrl ? "relay connected" : "no relay"}
            </span>
          </>
        )}
      </div>

      <div className="titlebar__tools">
        <button
          type="button"
          className="titlebar__button"
          onClick={onToggleTheme}
          aria-label={theme === "ink" ? "Switch to the parchment theme" : "Switch to the ink theme"}
          title={theme === "ink" ? "Parchment" : "Ink"}
        >
          <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" strokeWidth="1.4" />
            <path
              d={
                theme === "ink"
                  ? "M8 1.8 A6.2 6.2 0 0 1 8 14.2 Z"
                  : "M8 1.8 A6.2 6.2 0 0 0 8 14.2 Z"
              }
              fill="currentColor"
            />
          </svg>
        </button>
        {onSettings && (
          <button type="button" className="titlebar__button" onClick={onSettings}>
            Settings
          </button>
        )}
        {onLock && (
          <button
            type="button"
            className="titlebar__button titlebar__button--lock"
            onClick={onLock}
          >
            <svg viewBox="0 0 12 12" width="11" height="11" aria-hidden="true">
              <rect
                x="2"
                y="5.2"
                width="8"
                height="5.6"
                rx="1.2"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.2"
              />
              <path
                d="M4 5.2V3.8a2 2 0 0 1 4 0v1.4"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.2"
              />
            </svg>
            Lock
          </button>
        )}

        <div className="controls" aria-label="Window controls">
          <button
            type="button"
            className="controls__button"
            onClick={() => void windowAction("minimise")}
            aria-label="Minimise"
          >
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true">
              <path d="M1 5h8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
            </svg>
          </button>
          <button
            type="button"
            className="controls__button"
            onClick={() => void windowAction("maximise")}
            aria-label="Maximise"
          >
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true">
              <rect
                x="1.6"
                y="1.6"
                width="6.8"
                height="6.8"
                rx="1"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.2"
              />
            </svg>
          </button>
          <button
            type="button"
            className="controls__button controls__button--close"
            onClick={() => void windowAction("close")}
            aria-label="Close"
          >
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true">
              <path
                d="M2 2l6 6M8 2l-6 6"
                stroke="currentColor"
                strokeWidth="1.2"
                strokeLinecap="round"
              />
            </svg>
          </button>
        </div>
      </div>
    </header>
  );
}
