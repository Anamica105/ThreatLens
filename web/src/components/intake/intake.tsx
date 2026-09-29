"use client";

import clsx from "clsx";
import { Mail, Upload } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { Badge, Chip, Pill } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Table } from "@/components/ui/layout";
import { CLASSIFICATION, type Tone } from "@/lib/constants";
import { relative, utc } from "@/lib/format";

export interface IntakeUrl { url: string; host: string; kind: "article" | "indicator" | "noise"; include: boolean; reason: string }
export interface IntakeIoc { type: string; value: string; display: string }
export interface SuggestedWs { id: string; name: string; reason: string }

export interface IntakeItem {
  id: string;
  status: "parsed" | "needs_workspace" | "draft_created" | "dismissed";
  via: string;
  received_at: string;
  from: string;
  from_name?: string;
  subject: string;
  original: { from: string; subject: string; date: string } | null;
  note?: string;
  seed: string;
  urls: IntakeUrl[];
  cves: string[];
  actors: string[];
  malware: string[];
  iocs: IntakeIoc[];
  tlp: string | null;
  warnings: string[];
  suggested_workspace: SuggestedWs | null;
  research_id: string | null;
  run_id: string | null;
  message_id?: string;
}

export interface IntakeSummary extends Pick<IntakeItem, "id" | "status" | "via" | "received_at" | "from" | "subject" | "original" | "research_id" | "suggested_workspace"> {
  counts: { urls: number; cves: number; iocs: number };
}

export const INTAKE_STATUS: Record<IntakeItem["status"], { label: string; tone: Tone }> = {
  parsed: { label: "Ready to review", tone: "info" },
  needs_workspace: { label: "Needs workspace", tone: "warning" },
  draft_created: { label: "Draft created", tone: "success" },
  dismissed: { label: "Dismissed", tone: "muted" },
};

const MAX_BYTES = 10 * 1024 * 1024;

export function EmlDropZone({ onFile, busy }: { onFile: (f: File) => void; busy?: boolean }) {
  const input = useRef<HTMLInputElement | null>(null);
  const [over, setOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const take = (files: FileList | null) => {
    const f = files?.[0];
    if (!f) return;
    if (!/\.(eml|msg|txt)$/i.test(f.name) && f.type !== "message/rfc822") { setError("Choose an .eml file (save the email as a file, or drag it out of your mail client)."); return; }
    if (/\.msg$/i.test(f.name)) { setError("Outlook .msg files are not supported. Save the email as .eml, or forward it as an attachment to the intake address."); return; }
    if (f.size > MAX_BYTES) { setError("The email is larger than 10 MB."); return; }
    setError(null);
    onFile(f);
  };

  return (
    <div>
      <div
        role="button" tabIndex={0} aria-label="Drop an .eml file or choose one"
        onClick={() => input.current?.click()}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.current?.click(); } }}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); take(e.dataTransfer.files); }}
        className={clsx("flex cursor-pointer flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed px-4 py-10 text-center transition-colors",
          over ? "border-accent bg-accent-soft" : "border-line bg-surface hover:border-line-hover", busy && "pointer-events-none opacity-60")}>
        <Upload className="size-6 text-fg-muted" aria-hidden />
        <p className="text-[14px] font-semibold">{busy ? "Reading the email…" : "Drop an .eml file here"}</p>
        <p className="text-body-sm text-fg-muted">or click to choose one. Forwarded emails (attached or inline) are unwrapped to the original.</p>
        <input ref={input} type="file" accept=".eml,message/rfc822,.txt" className="sr-only" onChange={(e) => { take(e.target.files); e.target.value = ""; }} />
      </div>
      {error && <p className="mt-2 text-body-sm text-danger" role="alert">{error}</p>}
    </div>
  );
}

export function DetectedChips({ item }: { item: IntakeItem }) {
  const chips = [
    ...item.cves.map((c) => ({ key: c, label: c, dot: CLASSIFICATION.cve.color })),
    ...item.actors.map((a) => ({ key: a, label: a, dot: CLASSIFICATION.actor.color })),
    ...item.malware.map((m) => ({ key: m, label: m, dot: CLASSIFICATION.malware.color })),
  ];
  if (!chips.length && !item.iocs.length) return <p className="text-body-sm text-fg-muted">Nothing detected. The seed text is still usable.</p>;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {chips.map((c) => <Chip key={c.key} dot={c.dot}>{c.label}</Chip>)}
      {item.iocs.length > 0 && <Badge tone="neutral">{item.iocs.length} indicator{item.iocs.length > 1 ? "s" : ""}</Badge>}
    </div>
  );
}

const KIND_TONE: Record<IntakeUrl["kind"], Tone> = { article: "accent", indicator: "danger", noise: "muted" };

export function UrlToggleList({ urls, included, onToggle }: { urls: IntakeUrl[]; included: Set<string>; onToggle: (url: string) => void }) {
  const [showNoise, setShowNoise] = useState(false);
  const visible = urls.filter((u) => showNoise || u.kind !== "noise" || included.has(u.url));
  const hidden = urls.length - visible.length;
  if (!urls.length) return <p className="text-body-sm text-fg-muted">No links in this email.</p>;
  return (
    <div>
      <ul className="divide-y divide-line rounded-md border border-line">
        {visible.map((u) => {
          const on = included.has(u.url);
          const id = `url-${u.url}`;
          return (
            <li key={u.url} className="flex items-start gap-3 px-3 py-2">
              <input id={id} type="checkbox" className="mt-1 size-4 shrink-0 accent-[var(--accent)]" checked={on}
                disabled={u.kind === "indicator"} onChange={() => onToggle(u.url)} />
              <label htmlFor={id} className="min-w-0 flex-1 cursor-pointer">
                <span className="block break-all font-mono text-[12px]">{u.kind === "indicator" ? u.url.replace(/^http/i, "hxxp").replace(/\./g, "[.]") : u.url}</span>
                <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-caption text-fg-muted">
                  <Badge tone={KIND_TONE[u.kind]}>{u.kind === "article" ? "Article" : u.kind === "indicator" ? "Indicator" : "Noise"}</Badge>
                  {u.reason}
                </span>
              </label>
            </li>
          );
        })}
      </ul>
      {(hidden > 0 || showNoise) && (
        <button type="button" className="prose-link mt-2 text-body-sm" onClick={() => setShowNoise(!showNoise)}>
          {showNoise ? "Hide filtered links" : `Show ${hidden} filtered link${hidden > 1 ? "s" : ""} (tracking, unsubscribe, homepages)`}
        </button>
      )}
    </div>
  );
}

export function IocList({ iocs }: { iocs: IntakeIoc[] }) {
  const [all, setAll] = useState(false);
  if (!iocs.length) return null;
  const shown = all ? iocs : iocs.slice(0, 12);
  return (
    <div>
      <ul className="grid gap-1" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))" }}>
        {shown.map((i) => (
          <li key={`${i.type}|${i.value}`} className="flex min-w-0 items-center gap-2 text-[13px]">
            <Badge tone="neutral" className="w-16 justify-center">{i.type}</Badge>
            <span className="min-w-0 truncate font-mono text-[12px]" title={i.display}>{i.display}</span>
          </li>
        ))}
      </ul>
      {iocs.length > 12 && <button type="button" className="prose-link mt-2 text-body-sm" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${iocs.length}`}</button>}
    </div>
  );
}

export function RecentIntake({ items, onOpen, wsHref, activeId }:
  { items: IntakeSummary[]; onOpen: (id: string) => void; wsHref: (h: string) => string; activeId?: string }) {
  if (!items.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-8 text-center text-body-sm text-fg-muted">
        <Mail className="size-5" aria-hidden />
        No emails imported yet.
      </div>
    );
  }
  return (
    <Table compact>
      <thead>
        <tr><th>Received</th><th>Email</th><th>Found</th><th>Status</th><th><span className="sr-only">Action</span></th></tr>
      </thead>
      <tbody>
        {items.map((x) => {
          const st = INTAKE_STATUS[x.status] ?? INTAKE_STATUS.parsed;
          return (
            <tr key={x.id} className={clsx(activeId === x.id && "bg-accent-soft")}>
              <td className="whitespace-nowrap text-fg-muted" title={utc(x.received_at)}>{relative(x.received_at)}</td>
              <td className="min-w-0 max-w-[420px]">
                <span className="block truncate font-medium">{x.original?.subject || x.subject || "(no subject)"}</span>
                <span className="block truncate text-caption text-fg-muted">
                  {x.id} · {x.via.startsWith("webhook") ? "Inbound mail" : "Upload"} · {x.original?.from || x.from}
                </span>
              </td>
              <td className="whitespace-nowrap text-caption text-fg-muted">{x.counts.cves} CVE · {x.counts.iocs} IoC · {x.counts.urls} URL</td>
              <td><Pill tone={st.tone}>{st.label}</Pill></td>
              <td className="whitespace-nowrap text-right">
                {x.research_id
                  ? <Link className="prose-link" href={wsHref(`/research/${x.research_id}`)}>Open {x.research_id}</Link>
                  : x.status !== "dismissed" && <Button size="sm" onClick={() => onOpen(x.id)}>Review</Button>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
