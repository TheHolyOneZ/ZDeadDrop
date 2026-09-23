import type {
  Capsule,
  CapsuleDetail,
  CapsuleSpec,
  Finding,
  ItemPreview,
  ItemSpec,
  KeyInfo,
  Progress,
  RehearsalReport,
  SealState,
  Sealed,
  Shares,
  Status,
  TrusteeBehaviour,
  VaultSummary,
  Vigil,
} from "./types";

export const inTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export class Refusal extends Error {
  readonly locked: boolean;
  constructor(message: string) {
    super(message);
    this.locked = message === "the vault is locked";
  }
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!inTauri()) throw new Refusal("ZDeadDrop has to run inside its own window.");
  const { invoke } = await import("@tauri-apps/api/core");
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    throw new Refusal(typeof e === "string" ? e : "something went wrong");
  }
}

export async function listen<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
  if (!inTauri()) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(event, (e) => handler(e.payload));
}

export async function onFileDrop(
  handler: (e: { kind: "over" | "drop" | "leave"; paths: string[] }) => void,
): Promise<() => void> {
  if (!inTauri()) return () => {};
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((event) => {
    const p = event.payload;
    if (p.type === "over" || p.type === "enter") handler({ kind: "over", paths: [] });
    else if (p.type === "drop") handler({ kind: "drop", paths: p.paths });
    else handler({ kind: "leave", paths: [] });
  });
}

export const sealSvg = (seed: string, state: SealState, size: number, simplified = false) =>
  call<string>("seal_svg", { seed, state, size, simplified });

export const status = () => call<Status>("status");
export const createVault = (passphrase: string, strength: string, unrecoverable: boolean) =>
  call<void>("create_vault", { passphrase, strength, unrecoverable });
export const unlock = (passphrase: string) => call<void>("unlock", { passphrase });
export const unlockWithSheet = (words: string) => call<void>("unlock_with_sheet", { words });
export const lock = () => call<void>("lock");
export const touch = () => call<void>("touch");
export const loadVault = () => call<VaultSummary>("load_vault");
export const savePrefs = (
  checkinIntervalDays: number,
  graceDays: number,
  autoLockMinutes: number,
) => call<void>("save_prefs", { checkinIntervalDays, graceDays, autoLockMinutes });

export const beginRecoverySheet = () => call<string[]>("begin_recovery_sheet");
export const confirmRecoverySheet = (checks: [number, string][]) =>
  call<void>("confirm_recovery_sheet", { checks });
export const cancelRecoverySheet = () => call<void>("cancel_recovery_sheet");

export const loadVigil = () => call<Vigil>("load_vigil");

export const checkIn = (underDuress = false) => call<Vigil>("check_in", { underDuress });
export const setHold = (days: number) => call<Vigil>("set_hold", { days });
export const clearHold = () => call<Vigil>("clear_hold");
export const acknowledgeClock = () => call<Vigil>("acknowledge_clock");

export const loadCapsules = () => call<Capsule[]>("load_capsules");
export const capsuleDetail = (id: string) => call<CapsuleDetail>("capsule_detail", { id });
export const previewItem = (item: ItemSpec) => call<ItemPreview>("preview_item", { item });
export const inspectKey = (text: string) => call<KeyInfo>("inspect_key", { text });
export const pickPaths = (folders: boolean) => call<string[]>("pick_paths", { folders });
export const pickKeyFile = () => call<KeyInfo | null>("pick_key_file");
export const generateRecipientKey = (label: string) =>
  call<KeyInfo | null>("generate_recipient_key", { label });
export const sealCapsule = (spec: CapsuleSpec) => call<Sealed>("seal_capsule", { spec });
export const onSealProgress = (handler: (p: Progress) => void) =>
  listen<Progress>("seal-progress", handler);

export const pendingShares = (id: string) => call<Shares | null>("pending_shares", { id });
export const saveShare = (id: string, which: string) => call<boolean>("save_share", { id, which });
export const copyShare = (id: string, which: string) => call<void>("copy_share", { id, which });
export type LinkName = "home" | "source" | "author" | "projects" | "mods";
export const openLink = (which: LinkName) => call<void>("open_link", { which });
export const appVersion = () => call<string>("app_version");
export const revealVault = () => call<void>("reveal_vault");
export const copyText = (text: string) => call<void>("copy_text", { text });
export const sendRelayShare = (id: string) => call<void>("send_relay_share", { id });
export const finishShares = (id: string) => call<void>("finish_shares", { id });
export const reissueShares = (id: string) => call<void>("reissue_shares", { id });

export const updateTerms = (
  id: string,
  silenceDays: number,
  countdownDays: number,
  trustees: { name: string; contact: string | null }[],
  quorum: number,
) => call<boolean>("update_terms", { id, silenceDays, countdownDays, trustees, quorum });
export const verifyRecipient = (id: string, recipient: number) =>
  call<void>("verify_recipient", { id, recipient });
export const replaceRecipientKey = (id: string, recipient: number, key: string) =>
  call<void>("replace_recipient_key", { id, recipient, key });

export const exportCapsule = (id: string) => call<string | null>("export_capsule", { id });
export const releaseCapsule = (id: string, typedName: string) =>
  call<string | null>("release_capsule", { id, typedName });
export const deleteCapsule = (id: string, typedName: string) =>
  call<void>("delete_capsule", { id, typedName });

export const loadFindings = () => call<Finding[]>("load_findings");

export const connectRelay = (url: string, contact: string | null) =>
  call<void>("connect_relay", { url, contact });
export const disconnectRelay = () => call<void>("disconnect_relay");

export const rehearse = (
  quorum: number,
  trustees: number,
  behaviour: TrusteeBehaviour,
  answering: number,
  silenceDays?: number,
  countdownDays?: number,
) =>
  call<RehearsalReport>("run_rehearsal", {
    quorum,
    trustees,
    behaviour,
    answering,
    silenceDays: silenceDays ?? null,
    countdownDays: countdownDays ?? null,
  });

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function when(secs: number | null): string {
  if (!secs) return "never";
  return new Date(secs * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}
