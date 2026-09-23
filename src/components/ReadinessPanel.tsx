import { useEffect, useState } from "react";
import type { Finding } from "../lib/types";

const GLYPH: Record<Finding["severity"], string> = {
  critical: "!",
  warning: "△",
  note: "·",
};

interface Props {
  findings: Finding[];
  onAct: (finding: Finding) => void;
}

export function ReadinessPanel({ findings, onAct }: Props) {
  const order = { critical: 0, warning: 1, note: 2 } as const;
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  const [open, setOpen] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const worst = sorted[0]?.id;
  useEffect(() => {
    if (!touched && worst) setOpen(worst);
  }, [worst, touched]);

  const toggle = (id: string) => {
    setTouched(true);
    setOpen((current) => (current === id ? null : id));
  };

  const critical = sorted.filter((f) => f.severity === "critical").length;

  if (sorted.length === 0) {
    return (
      <section className="readiness" aria-labelledby="readiness-rubric">
        <h2 className="rubric" id="readiness-rubric">
          Readiness
        </h2>
        <p className="readiness__clear">
          <span className="readiness__clearmark" aria-hidden="true">
            ✓
          </span>
          Nothing would stop a release today.
        </p>
      </section>
    );
  }

  return (
    <section className="readiness" aria-labelledby="readiness-rubric">
      <h2 className="rubric" id="readiness-rubric">
        Readiness
        <span className="rubric__count">
          {sorted.length} {sorted.length === 1 ? "item" : "items"}
          {critical > 0 && ` · ${critical} critical`}
        </span>
      </h2>

      <ul className="readiness__list">
        {sorted.map((f) => {
          const expanded = open === f.id;
          return (
            <li key={f.id} className={`finding finding--${f.severity}`}>
              <button
                type="button"
                className="finding__head"
                onClick={() => toggle(f.id)}
                aria-expanded={expanded}
              >
                <span className={`finding__glyph finding__glyph--${f.severity}`} aria-hidden="true">
                  {GLYPH[f.severity]}
                </span>
                <span className="finding__title">{f.title}</span>
                <span className="finding__chevron" aria-hidden="true" data-open={expanded}>
                  ⌄
                </span>
              </button>

              {expanded && (
                <div className="finding__body">
                  <p className="finding__detail">{f.detail}</p>
                  {f.action && (
                    <button type="button" className="finding__action" onClick={() => onAct(f)}>
                      {f.action}
                    </button>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
