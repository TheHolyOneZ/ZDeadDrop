import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";

import { copyText } from "../lib/api";
import { HoldToConfirm } from "./HoldToConfirm";

type Tone = "good" | "bad" | "plain";
interface Toast {
  id: number;
  tone: Tone;
  text: string;
}

const ToastContext = createContext<(text: string, tone?: Tone) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);

  const push = useCallback((text: string, tone: Tone = "plain") => {
    const id = next.current++;
    setToasts((t) => [...t.slice(-2), { id, tone, text }]);
    window.setTimeout(
      () => setToasts((t) => t.filter((x) => x.id !== id)),
      tone === "bad" ? 7000 : 3600,
    );
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast--${t.tone}`}
            onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}
            title="Dismiss"
          >
            <span className="toast__mark" aria-hidden="true">
              {t.tone === "good" ? "✓" : t.tone === "bad" ? "!" : "·"}
            </span>
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

export function say(e: unknown): string {
  if (e instanceof Error) return e.message.charAt(0).toUpperCase() + e.message.slice(1);
  return "Something went wrong.";
}

function useEscape(onClose: (() => void) | undefined) {
  useEffect(() => {
    if (!onClose) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
}

interface ModalProps {
  title: string;
  kicker?: string;
  onClose?: (() => void) | undefined;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}

export function Modal({ title, kicker, onClose, children, footer, wide }: ModalProps) {
  useEscape(onClose);

  return createPortal(
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div
        className={`modal ${wide ? "modal--wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header className="modal__head">
          <div>
            {kicker && <p className="modal__kicker">{kicker}</p>}
            <h2 className="modal__title serif">{title}</h2>
          </div>
          {onClose && (
            <button type="button" className="iconbtn" onClick={onClose} aria-label="Close">
              <svg viewBox="0 0 10 10" width="11" height="11" aria-hidden="true">
                <path
                  d="M2 2l6 6M8 2l-6 6"
                  stroke="currentColor"
                  strokeWidth="1.3"
                  strokeLinecap="round"
                />
              </svg>
            </button>
          )}
        </header>
        <div className="modal__body">{children}</div>
        {footer && <footer className="modal__foot">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

export function Drawer({
  onClose,
  children,
  label,
}: {
  onClose: () => void;
  children: ReactNode;
  label: string;
}) {
  useEscape(onClose);
  return createPortal(
    <div
      className="overlay overlay--drawer"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={label}>
        <button
          type="button"
          className="iconbtn drawer__close"
          onClick={onClose}
          aria-label="Close"
        >
          <svg viewBox="0 0 10 10" width="11" height="11" aria-hidden="true">
            <path
              d="M2 2l6 6M8 2l-6 6"
              stroke="currentColor"
              strokeWidth="1.3"
              strokeLinecap="round"
            />
          </svg>
        </button>
        {children}
      </aside>
    </div>,
    document.body,
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="spinner" role="progressbar" aria-label={label ?? "Working"}>
      <span className="spinner__ring" aria-hidden="true" />
      {label && <span className="spinner__label">{label}</span>}
    </span>
  );
}

export function TypeAndHold({
  name,
  action,
  onConfirm,
  busy,
}: {
  name: string;
  action: string;
  onConfirm: (typed: string) => void;
  busy?: boolean;
}) {
  const [typed, setTyped] = useState("");
  const matches = typed.trim() === name.trim();
  return (
    <div className="typehold">
      <label className="field">
        <span className="field__label">
          Type <strong className="typehold__name">{name}</strong> to confirm
        </span>
        <input
          className="input"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
      </label>
      <div className="typehold__hold" data-ready={matches}>
        {busy ? (
          <Spinner label="Working" />
        ) : (
          <HoldToConfirm
            key={String(matches)}
            label={action}
            onConfirm={() => matches && onConfirm(typed)}
          />
        )}
      </div>
    </div>
  );
}

export function Stepper({
  value,
  min,
  max,
  onChange,
  suffix,
  label,
}: {
  value: number;
  min: number;
  max: number;
  onChange: (n: number) => void;
  suffix?: string;
  label: string;
}) {
  const clamp = (n: number) => Math.max(min, Math.min(max, n));
  return (
    <div className="stepper" role="group" aria-label={label}>
      <button
        type="button"
        onClick={() => onChange(clamp(value - 1))}
        disabled={value <= min}
        aria-label={`Fewer ${label}`}
      >
        −
      </button>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={(e) => onChange(clamp(Number(e.target.value) || min))}
        aria-label={label}
      />
      {suffix && <span className="stepper__suffix">{suffix}</span>}
      <button
        type="button"
        onClick={() => onChange(clamp(value + 1))}
        disabled={value >= max}
        aria-label={`More ${label}`}
      >
        +
      </button>
    </div>
  );
}

export function Chips<T extends string | number>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string; hint?: string }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="chips" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          className="chip"
          data-on={o.value === value}
          onClick={() => onChange(o.value)}
        >
          <span className="chip__label">{o.label}</span>
          {o.hint && <span className="chip__hint">{o.hint}</span>}
        </button>
      ))}
    </div>
  );
}

export type MenuEntry =
  | {
      label: string;
      onSelect: () => void;
      hint?: string;
      danger?: boolean;
      disabled?: boolean;
    }
  | "separator";

type OpenMenu = (
  e: { clientX: number; clientY: number; preventDefault: () => void; stopPropagation: () => void },
  items: MenuEntry[],
) => void;

const MenuContext = createContext<OpenMenu>(() => {});

export function ContextMenuProvider({ children }: { children: ReactNode }) {
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuEntry[] } | null>(null);
  const [active, setActive] = useState(0);
  const ref = useRef<HTMLDivElement>(null);

  const open = useCallback<OpenMenu>((e, items) => {
    e.preventDefault();
    e.stopPropagation();
    setMenu({ x: e.clientX, y: e.clientY, items });
    setActive(items.findIndex((i) => i !== "separator" && !i.disabled));
  }, []);

  useEffect(() => {
    const suppress = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest("input, textarea, [contenteditable='true']")) return;
      e.preventDefault();
    };
    document.addEventListener("contextmenu", suppress);
    return () => document.removeEventListener("contextmenu", suppress);
  }, []);

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const onKey = (e: KeyboardEvent) => {
      const selectable = menu.items
        .map((item, i) => (item !== "separator" && !item.disabled ? i : -1))
        .filter((i) => i >= 0);
      if (e.key === "Escape") close();
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const at = selectable.indexOf(active);
        const next = e.key === "ArrowDown" ? at + 1 : at - 1;
        setActive(selectable[(next + selectable.length) % selectable.length] ?? active);
      } else if (e.key === "Enter") {
        e.preventDefault();
        const item = menu.items[active];
        if (item && item !== "separator" && !item.disabled) {
          close();
          item.onSelect();
        }
      }
    };
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) close();
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onDown);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [menu, active]);

  const style = menu
    ? {
        left: Math.min(menu.x, window.innerWidth - 248),
        top: Math.min(menu.y, window.innerHeight - (menu.items.length * 34 + 16)),
      }
    : undefined;

  return (
    <MenuContext.Provider value={open}>
      {children}
      {menu &&
        createPortal(
          <div ref={ref} className="ctxmenu" role="menu" style={style}>
            {menu.items.map((item, i) =>
              item === "separator" ? (
                <div key={i} className="ctxmenu__sep" role="separator" />
              ) : (
                <button
                  key={i}
                  type="button"
                  role="menuitem"
                  className={`ctxmenu__item ${item.danger ? "ctxmenu__item--danger" : ""}`}
                  data-active={i === active}
                  disabled={item.disabled}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => {
                    setMenu(null);
                    item.onSelect();
                  }}
                >
                  <span>{item.label}</span>
                  {item.hint && <kbd className="ctxmenu__hint">{item.hint}</kbd>}
                </button>
              ),
            )}
          </div>,
          document.body,
        )}
    </MenuContext.Provider>
  );
}

export const useContextMenu = () => useContext(MenuContext);

export function CopyCode({
  text,
  className,
  label,
}: {
  text: string;
  className?: string;
  label?: string;
}) {
  const toast = useToast();
  const menu = useContextMenu();
  const copy = () =>
    copyText(text).then(
      () => toast(`${label ?? "Code"} copied: ${text}`, "good"),
      (e) => toast(say(e), "bad"),
    );
  return (
    <button
      type="button"
      className={`copycode mono ${className ?? ""}`}
      title="Click to copy"
      onClick={(e) => {
        e.stopPropagation();
        void copy();
      }}
      onContextMenu={(e) =>
        menu(e, [{ label: `Copy ${label?.toLowerCase() ?? "code"}`, onSelect: () => void copy() }])
      }
    >
      {text}
    </button>
  );
}
