const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function when(epoch: number | null | undefined, withTime = false): string {
  if (!epoch) return "—";
  return (withTime ? dateTime : date).format(new Date(epoch * 1000));
}

export function fromNow(epoch: number): string {
  const days = Math.round((epoch * 1000 - Date.now()) / 86_400_000);
  if (Math.abs(days) >= 1) return relative.format(days, "day");
  const hours = Math.round((epoch * 1000 - Date.now()) / 3_600_000);
  return relative.format(hours, "hour");
}

// <input type="datetime-local"> speaks local wall time without a zone; the API wants ISO 8601
// with one, so a picked time keeps its meaning wherever the server runs.
export function localInputToIso(value: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

export function epochToLocalInput(epoch: number | null): string {
  if (!epoch) return "";
  const d = new Date(epoch * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function expiryState(epoch: number | null): "none" | "expired" | "soon" | "later" {
  if (!epoch) return "none";
  const left = epoch * 1000 - Date.now();
  if (left <= 0) return "expired";
  return left < 30 * 86_400_000 ? "soon" : "later";
}
