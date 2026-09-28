/** Dates: absolute ISO + UTC in reports; relative in lists with the absolute value in a tooltip. */

export function toDate(v: string | Date | null | undefined): Date | null {
  if (!v) return null;
  if (v instanceof Date) return v;
  const s = /[zZ]|[+-]\d\d:?\d\d$/.test(v) || v.length <= 10 ? v : v + "Z";
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

const pad = (n: number) => String(n).padStart(2, "0");

export function utc(v: string | Date | null | undefined, withTime = true): string {
  const d = toDate(v);
  if (!d) return "—";
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  return withTime ? `${date} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC` : date;
}

export function relative(v: string | Date | null | undefined): string {
  const d = toDate(v);
  if (!d) return "—";
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  const days = Math.round(s / 86400);
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  if (days < 365) return `${Math.round(days / 30)} mo ago`;
  return `${Math.round(days / 365)} y ago`;
}

export function num(n: number | null | undefined, compact = false): string {
  if (n === null || n === undefined) return "—";
  if (compact && Math.abs(n) >= 10000) return `${(n / 1000).toFixed(1)}k`;
  return n.toLocaleString("en-US");
}

export function duration(sec: number): string {
  if (!isFinite(sec) || sec < 0) return "—";
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  if (m >= 60) return `${Math.floor(m / 60)} h ${m % 60} min`;
  return m ? `${m} min ${s} s` : `${s} s`;
}

export function elapsed(start?: string | null, end?: string | null): string {
  const a = toDate(start);
  if (!a) return "";
  const b = toDate(end) ?? new Date();
  const s = Math.max(0, (b.getTime() - a.getTime()) / 1000);
  return `${Math.floor(s / 60)}:${pad(Math.floor(s % 60))}`;
}

export function sentence(s: string): string {
  const t = s.replace(/_/g, " ");
  return t.charAt(0).toUpperCase() + t.slice(1);
}

/* Indicators: always defanged on screen. */
export function refang(v: string): string {
  return v.replace(/hxxp/gi, "http").replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".").replace(/\[:\]/g, ":").replace(/\[@\]/g, "@");
}

export function defang(v: string, type?: string): string {
  const r = refang(v);
  if (type && ["sha256", "sha1", "md5", "file_name", "file_path", "registry", "mutex", "user_agent", "cve", "wallet"].includes(type)) return r;
  if (type === "ipv4" || /^\d{1,3}(\.\d{1,3}){3}$/.test(r)) {
    const i = r.lastIndexOf(".");
    return `${r.slice(0, i)}[.]${r.slice(i + 1)}`;
  }
  const m = /^(https?|ftp)(:\/\/)([^/]+)(.*)$/i.exec(r);
  if (m) return `${m[1].replace(/^http/i, "hxxp")}${m[2]}${m[3].replace(/\./g, "[.]")}${m[4]}`;
  if (type === "email") return r.replace("@", "[@]").replace(/\./g, "[.]");
  return r.replace(/\./g, "[.]");
}

export function truncateMiddle(v: string, head = 8, tail = 8): string {
  return v.length > head + tail + 1 ? `${v.slice(0, head)}…${v.slice(-tail)}` : v;
}

export function isHash(type: string) {
  return type === "sha256" || type === "sha1" || type === "md5";
}

export function plural(n: number, one: string, many?: string) {
  return `${num(n)} ${n === 1 ? one : many ?? one + "s"}`;
}
