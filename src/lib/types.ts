export type SealState = "sealed" | "stirring" | "breaking" | "broken" | "held" | "frozen";

export type StageKind =
  | "held"
  | "grace"
  | "escalating"
  | "awaiting_quorum"
  | "countdown"
  | "ready_to_release"
  | "released"
  | "cancelled"
  | "on_hold"
  | "frozen";

export interface Status {
  exists: boolean;
  unlocked: boolean;
  shortId: string | null;
  sealSeed: string | null;
  path: string;
  recoveryPolicy: "standard" | "unrecoverable" | null;
}

export interface RelayState {
  url: string;
  lastReceiptAt: number | null;
  lastError: string | null;
}

export interface Vigil {
  stage: StageKind;
  summary: string;
  silenceSecs: number;
  dueInSecs: number;
  intervalSecs: number;
  counter: number;
  frozenReason: string | null;
  holdUntil: number | null;
  maxHoldDays: number;
  relay: RelayState | null;
}

export interface Capsule {
  id: string;
  sealSeed: string;
  fingerprint: string;

  figure: string;
  name: string;
  state: SealState;
  stage: StageKind;
  condition: string;
  recipientCount: number;
  quorum: { have: number; need: number; of: number } | null;
  sizeBytes: number;
  entryCount: number;
  isRehearsal: boolean;
  createdAt: number;
  releasedAt: number | null;
  sharesPending: boolean;
  sharesDistributed: boolean;
  exportedAt: number | null;
  silenceDays: number;
  countdownDays: number;
}

export interface Recipient {
  id: number;
  label: string;
  fingerprint: string;
  sealSeed: string;
  figure: string;
  tier: number;
  claimWindowDays: number;
  verifiedAt: number | null;
  rotatedAt: number | null;
}

export interface Entry {
  path: string;
  size: number;
  kind: string;
}

export interface CapsuleDetail {
  capsule: Capsule;
  note: string | null;
  silenceDays: number;
  countdownDays: number;
  trustees: string[];
  trusteeContacts: (string | null)[];
  recipients: Recipient[];
  entries: Entry[];
  policyWeakness: string | null;
}

export interface Finding {
  id: string;
  severity: "critical" | "warning" | "note";
  title: string;
  detail: string;
  action: string | null;
  target: string | null;
}

export interface VaultSummary {
  shortId: string;
  vigilFingerprint: string;
  vigilSeed: string;
  recoveryPolicy: "standard" | "unrecoverable";
  unlockPaths: string[];
  relayUrl: string | null;
  ownerContact: string | null;
  trusteeCount: number;
  checkinIntervalDays: number;
  graceDays: number;
  autoLockMinutes: number;
  recoverySheetAt: number | null;
  lastRehearsalAt: number | null;
  path: string;
}

export interface KeyInfo {
  fingerprint: string;
  sealSeed: string;
  figure: string;
  publicKey: string;

  wasPrivate: boolean;
}

export interface ShareSlot {
  which: string;
  holder: string;
  handedOut: boolean;
}

export interface Shares {
  capsule: string;
  seal: string;
  relayConnected: boolean;
  relay: ShareSlot | null;
  trustees: ShareSlot[];
}

export interface Sealed {
  id: string;
  name: string;
  skipped: string[];
}

export interface ItemPreview {
  title: string;
  detail: string;
  kind: "file" | "folder" | "note" | "seed" | "totp" | "codes" | "login";
  files: number;
  bytes: number;
  skipped: string[];
}

export type ItemSpec =
  | { type: "path"; path: string }
  | { type: "note"; label: string; text: string }
  | { type: "seedPhrase"; label: string; words: string }
  | { type: "totp"; uri: string }
  | { type: "recoveryCodes"; label: string; text: string }
  | { type: "import"; path: string; password: string | null }
  | { type: "credential"; label: string; username: string; password: string; url: string };

export interface RecipientSpec {
  label: string;
  publicKey: string;
  tier: number;
  claimWindowDays: number;
  verified: boolean;
}

export interface CapsuleSpec {
  name: string;
  note: string | null;
  items: ItemSpec[];
  recipients: RecipientSpec[];
  trustees: { name: string; contact: string | null }[];
  quorum: number;
  silenceDays: number;
  countdownDays: number;
}

export interface RehearsalMoment {
  day: number;
  stage: StageKind;
  lines: string[];
}

export interface RehearsalConcern {
  severity: "blocking" | "warning";
  title: string;
  detail: string;
}

export interface RehearsalReport {
  verdict: string;
  wouldRelease: boolean;
  releasedOn: number | null;
  timeline: RehearsalMoment[];
  concerns: RehearsalConcern[];
}

export type TrusteeBehaviour = "all-answer" | "some-answer" | "one-vetoes" | "nobody-answers";

export interface Progress {
  phase: string;
  done: number;
  total: number;
}
