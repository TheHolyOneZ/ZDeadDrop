import { bytes as size } from "../lib/api";
import { Seal } from "./Seal";
import type { Capsule } from "../lib/types";

interface Props {
  capsule: Capsule;
  onOpen: (id: string) => void;

  onMenu?: (e: React.MouseEvent) => void;
}

export function CapsuleCard({ capsule, onOpen, onMenu }: Props) {
  return (
    <button
      type="button"
      className={`capsule capsule--${capsule.state}`}
      onClick={() => onOpen(capsule.id)}
      onContextMenu={onMenu}
      title="Open · right-click for more"
      aria-label={`${capsule.name}, ${capsule.state}. ${capsule.condition}`}
    >
      <div className="capsule__sealwrap">
        <Seal seed={capsule.sealSeed} state={capsule.state} size={104} />
        {capsule.isRehearsal && <span className="capsule__drill">drill</span>}
        {capsule.sharesPending && <span className="capsule__flag">pieces to hand out</span>}
      </div>

      <div className="capsule__name serif">{capsule.name}</div>

      <div className="capsule__state">
        <span className={`capsule__pip capsule__pip--${capsule.state}`} aria-hidden="true" />
        {capsule.releasedAt ? "released" : capsule.state}
      </div>

      <div className="capsule__fingerprint mono selectable">{capsule.fingerprint}</div>

      <dl className="capsule__facts">
        <div>
          <dt>Holds</dt>
          <dd>
            {size(capsule.sizeBytes)} · {capsule.entryCount}{" "}
            {capsule.entryCount === 1 ? "item" : "items"}
          </dd>
        </div>
        <div>
          <dt>Goes to</dt>
          <dd>
            {capsule.recipientCount} {capsule.recipientCount === 1 ? "person" : "people"}
          </dd>
        </div>
        <div>
          <dt>Quorum</dt>
          <dd>
            {capsule.quorum ? (
              `${capsule.quorum.need} of ${capsule.quorum.of} trustees`
            ) : (
              <span className="capsule__noquorum">none — relay alone</span>
            )}
          </dd>
        </div>
      </dl>

      <p className="capsule__condition">{capsule.condition}</p>
    </button>
  );
}

export function NewCapsuleCard({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" className="capsule capsule--new" onClick={onClick}>
      <div className="capsule__sealwrap">
        <div className="capsule__blank" aria-hidden="true">
          <svg viewBox="0 0 104 104" width="104" height="104">
            <circle
              cx="52"
              cy="52"
              r="42"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeDasharray="4 6"
              opacity="0.5"
            />
            <path
              d="M52 38 L52 66 M38 52 L66 52"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              opacity="0.8"
            />
          </svg>
        </div>
      </div>
      <div className="capsule__name serif">New capsule</div>
      <p className="capsule__condition">
        Choose what to seal, who receives it, and what silence means.
      </p>
    </button>
  );
}
