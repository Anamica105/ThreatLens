"use client";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const USER_KEY = "tl.user";

export function getUserId(): string | null {
  try {
    return localStorage.getItem(USER_KEY);
  } catch {
    return null;
  }
}

export function setUserId(id: string) {
  try {
    localStorage.setItem(USER_KEY, id);
  } catch {
    /* storage unavailable */
  }
}

function headers(extra?: HeadersInit): HeadersInit {
  const h: Record<string, string> = { Accept: "application/json" };
  const u = getUserId();
  if (u) h["X-User"] = u;
  return { ...h, ...(extra as Record<string, string>) };
}

async function parseError(res: Response): Promise<ApiError> {
  let msg = `Request failed (${res.status})`;
  try {
    const body = await res.json();
    if (typeof body.detail === "string") msg = body.detail;
    else if (Array.isArray(body.detail)) msg = body.detail.map((d: { msg: string; loc?: string[] }) => `${d.loc?.slice(-1)[0] ?? ""} ${d.msg}`.trim()).join("; ");
  } catch {
    /* not JSON */
  }
  if (res.status === 502 || res.status === 500 && msg.startsWith("Request failed")) msg = "The ThreatLens API is not reachable. Start it with the run-api script.";
  return new ApiError(res.status, msg);
}

export async function api<T = unknown>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const { json, ...rest } = init ?? {};
  const res = await fetch(path, {
    ...rest,
    headers: headers(json !== undefined ? { "Content-Type": "application/json" } : undefined),
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const get = <T,>(path: string) => api<T>(path);
export const post = <T,>(path: string, json?: unknown) => api<T>(path, { method: "POST", json: json ?? {} });
export const put = <T,>(path: string, json?: unknown) => api<T>(path, { method: "PUT", json });
export const patch = <T,>(path: string, json?: unknown) => api<T>(path, { method: "PATCH", json });

/** Fetch a file and hand it to the browser as a download. Returns the file name. */
export async function download(path: string, init?: RequestInit & { json?: unknown }): Promise<string> {
  const { json, ...rest } = init ?? {};
  const res = await fetch(path, {
    ...rest,
    headers: headers(json !== undefined ? { "Content-Type": "application/json" } : undefined),
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  if (!res.ok) throw await parseError(res);
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const name = /filename="?([^"]+)"?/.exec(cd)?.[1] || "export";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return name;
}

export async function fetchText(path: string): Promise<string> {
  const res = await fetch(path, { headers: headers() });
  if (!res.ok) throw await parseError(res);
  return res.text();
}

export function qs(params: Record<string, string | number | boolean | string[] | undefined | null>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === false) continue;
    if (Array.isArray(v)) v.forEach((x) => u.append(k, x));
    else u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}
