import { useCallback, useEffect, useRef, useState } from "react";

interface Props {
  label: string;

  holdMs?: number;
  onConfirm: () => void;
  tone?: "danger" | "neutral";
}

export function HoldToConfirm({ label, holdMs = 2000, onConfirm, tone = "danger" }: Props) {
  const [progress, setProgress] = useState(0);
  const [done, setDone] = useState(false);
  const started = useRef<number | null>(null);
  const frame = useRef<number | null>(null);

  const stop = useCallback(() => {
    started.current = null;
    if (frame.current !== null) cancelAnimationFrame(frame.current);
    frame.current = null;
    setProgress(0);
  }, []);

  const tick = useCallback(() => {
    if (started.current === null) return;
    const elapsed = performance.now() - started.current;
    const ratio = Math.min(1, elapsed / holdMs);
    setProgress(ratio);

    if (ratio >= 1) {
      started.current = null;
      setDone(true);
      onConfirm();

      window.setTimeout(() => {
        setDone(false);
        setProgress(0);
      }, 1400);
      return;
    }
    frame.current = requestAnimationFrame(tick);
  }, [holdMs, onConfirm]);

  const begin = useCallback(() => {
    if (done) return;
    started.current = performance.now();
    frame.current = requestAnimationFrame(tick);
  }, [done, tick]);

  useEffect(() => () => stop(), [stop]);

  const circumference = 2 * Math.PI * 15;

  return (
    <button
      type="button"
      className={`hold hold--${tone}`}
      data-armed={progress > 0}
      onPointerDown={begin}
      onPointerUp={stop}
      onPointerLeave={stop}
      onPointerCancel={stop}

      onKeyDown={(e) => {
        if ((e.key === " " || e.key === "Enter") && !e.repeat) {
          e.preventDefault();
          begin();
        }
      }}
      onKeyUp={(e) => {
        if (e.key === " " || e.key === "Enter") stop();
      }}
      aria-label={`${label}. Press and hold for two seconds to confirm.`}
    >
      <svg className="hold__ring" viewBox="0 0 34 34" width="34" height="34" aria-hidden="true">
        <circle cx="17" cy="17" r="15" className="hold__track" />
        <circle
          cx="17"
          cy="17"
          r="15"
          className="hold__sweep"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - progress)}
        />
      </svg>
      <span className="hold__label">{done ? "Done" : label}</span>
      <span className="hold__hint faint">{progress > 0 ? "keep holding" : "hold"}</span>
    </button>
  );
}
