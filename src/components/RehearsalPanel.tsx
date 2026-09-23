import { useCallback, useEffect, useState } from "react";

import { rehearse } from "../lib/api";
import type { RehearsalReport, TrusteeBehaviour } from "../lib/types";

const BEHAVIOURS: { value: TrusteeBehaviour; label: string; hint: string }[] = [
  { value: "all-answer", label: "Everyone answers", hint: "the best case" },
  { value: "some-answer", label: "Only some answer", hint: "the likely case" },
  { value: "one-vetoes", label: "One says you're fine", hint: "a mistaken trustee" },
  { value: "nobody-answers", label: "Nobody answers", hint: "the worst case" },
];

export function RehearsalPanel({
  initialQuorum = 3,
  initialTrustees = 5,
  silenceDays,
  countdownDays,
}: {
  initialQuorum?: number;
  initialTrustees?: number;
  silenceDays?: number;
  countdownDays?: number;
}) {
  const [behaviour, setBehaviour] = useState<TrusteeBehaviour>("some-answer");
  const [quorum, setQuorum] = useState(initialQuorum);
  const [trustees, setTrustees] = useState(initialTrustees);
  const [report, setReport] = useState<RehearsalReport | null>(null);
  const [running, setRunning] = useState(false);

  const run = useCallback(
    (which: TrusteeBehaviour) => {
      setBehaviour(which);
      setRunning(true);
      void rehearse(quorum, trustees, which, Math.max(1, quorum - 1), silenceDays, countdownDays)
        .then(setReport, () => {})
        .finally(() => setRunning(false));
    },
    [quorum, trustees, silenceDays, countdownDays],
  );

  useEffect(() => {
    run(behaviour);
  }, [quorum, trustees, silenceDays, countdownDays]);

  return (
    <section className="rehearsal" aria-labelledby="rehearsal-rubric">
      <h2 className="rubric" id="rehearsal-rubric">
        Rehearsal
        {report && (
          <span className="rubric__count">
            {report.wouldRelease ? "would deliver" : "would not deliver"}
          </span>
        )}
      </h2>

      <div className="rehearsal__intro">
        <p className="rehearsal__blurb">
          Run the whole release now, against a pretend clock. Months pass in a moment and nothing
          real is touched — no message is sent, no capsule moves. It is the only way to find out
          your setup is wrong while you can still fix it.
        </p>

        <div className="rehearsal__dials">
          <label className="dial">
            <span className="dial__label">Quorum</span>
            <input
              type="number"
              min={0}
              max={trustees}
              value={quorum}
              onChange={(e) => setQuorum(Number(e.target.value))}
            />
          </label>
          <span className="dial__of">of</span>
          <label className="dial">
            <span className="dial__label">Trustees</span>
            <input
              type="number"
              min={1}
              max={16}
              value={trustees}
              onChange={(e) => setTrustees(Number(e.target.value))}
            />
          </label>
        </div>
      </div>

      <div className="rehearsal__choices" role="group" aria-label="What your trustees do">
        {BEHAVIOURS.map((b) => (
          <button
            key={b.value}
            type="button"
            className="choice"
            data-selected={behaviour === b.value}
            onClick={() => run(b.value)}
            disabled={running}
          >
            <span className="choice__label">{b.label}</span>
            <span className="choice__hint faint">{b.hint}</span>
          </button>
        ))}
      </div>

      {report && (
        <div className="rehearsal__result">
          <p
            className={`rehearsal__verdict rehearsal__verdict--${
              report.wouldRelease ? "good" : "bad"
            }`}
          >
            {report.verdict}
          </p>

          <ol className="timeline">
            {report.timeline.map((moment) => (
              <li key={moment.day} className={`timeline__moment timeline__moment--${moment.stage}`}>
                <span className="timeline__day mono">day {moment.day}</span>
                <div className="timeline__lines">
                  {moment.lines.map((line) => (
                    <p key={line}>{line}</p>
                  ))}
                </div>
              </li>
            ))}
          </ol>

          {report.concerns.length > 0 && (
            <div className="rehearsal__concerns">
              <h3 className="rehearsal__subhead">What to fix</h3>
              {report.concerns.map((concern) => (
                <div key={concern.title} className={`concern concern--${concern.severity}`}>
                  <p className="concern__title">{concern.title}</p>
                  <p className="concern__detail">{concern.detail}</p>
                </div>
              ))}
            </div>
          )}

          {report.concerns.length === 0 && (
            <p className="rehearsal__clear">
              Nothing about this configuration would stop it working.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
