"use client";

import { ChevronRight, MessageSquare } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { get, post } from "@/lib/api";
import { relative, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { User } from "@/lib/types";
import { Avatar, Badge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { Alert, useToast } from "../../ui/feedback";
import { Textarea } from "../../ui/forms";
import { Panel } from "../../ui/layout";
import { Dialog } from "../../ui/overlay";
import { ClaimConflict } from "../claim-conflict";
import { SourceCard } from "../source-card";
import type { DetailProps } from "./common";

export function SourcesTab({ d, reload }: DetailProps) {
  const rec = d.record;
  const toast = useToast();
  const sources = useMemo(() => Object.fromEntries(rec.sources.map((s) => [s.id, s])), [rec.sources]);
  const editable = d.status === "draft" || d.status === "failed";
  const [changed, setChanged] = useState(false);
  useEffect(() => {
    if (location.hash) setTimeout(() => document.querySelector(location.hash)?.scrollIntoView({ block: "start" }), 50);
  }, []);
  const toggle = async (sid: string, included: boolean) => {
    try {
      await post(`/api/research/${d.id}/sources/${sid}`, { included });
      setChanged(true);
      reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };
  const rerun = async () => {
    await post(`/api/research/${d.id}/rerun`, { from_stage: "synthesis" });
    toast({ tone: "info", message: "Re-running synthesis with the selected sources" });
    location.href = `/research/${d.id}/run`;
  };
  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
      <div className="space-y-4">
        {changed && <Alert tone="info" title="Source selection changed" action={<Button size="sm" onClick={rerun}>Re-run synthesis</Button>}>Synthesis must re-run to reflect included and excluded sources.</Alert>}
        {rec.sources.map((s) => <SourceCard key={s.id} s={s} conflicts={rec.conflicts} editable={editable} onToggle={(v) => toggle(s.id, v)} />)}
        {!rec.sources.length && <p className="text-fg-muted">No sources recorded.</p>}
      </div>
      <div className="space-y-4">
        <Panel title="Conflicts">
          {rec.conflicts.length ? <div className="space-y-3">{rec.conflicts.map((c, i) => <ClaimConflict key={i} c={c} sources={sources} />)}</div> : <p className="text-fg-muted">The sources agree on the facts used.</p>}
        </Panel>
        <Panel title="Admiralty scale">
          <p className="text-body-sm text-fg-strong">Ratings combine source reliability (A completely reliable … F cannot be judged) and information credibility (1 confirmed … 6 cannot be judged).</p>
        </Panel>
      </div>
    </div>
  );
}

interface Activity {
  events: { id: number; type: string; message: string; user: User | null; created_at: string; meta: Record<string, unknown> }[];
  exports: { format: string; workspace_id: string | null; user: User | null; created_at: string; file_name: string }[];
}
interface Version { version: number; changed_by: User | null; changed_at: string; summary: string; diff: { changed_sections?: string[] } }

const DOT: Record<string, string> = { created: "var(--accent)", run_completed: "var(--accent)", status: "var(--success)", edited: "var(--info)", exported: "var(--g-400)", result: "var(--sev-medium)", comment: "var(--text-secondary)" };

export function ActivityTab({ d }: DetailProps) {
  const { data, reload } = useApi<Activity>(`/api/research/${d.id}/activity`);
  const { data: versions } = useApi<Version[]>(`/api/research/${d.id}/versions`);
  const [comment, setComment] = useState("");
  const [diff, setDiff] = useState<{ v: number; a: Record<string, unknown>; b: Record<string, unknown>; sections: string[] } | null>(null);
  const toast = useToast();

  const send = async () => {
    if (!comment.trim()) return;
    await post(`/api/research/${d.id}/comments`, { message: comment });
    setComment("");
    toast({ tone: "success", message: "Comment added" });
    reload();
  };
  const viewDiff = async (v: Version) => {
    const cur = await get<{ record: Record<string, unknown> }>(`/api/research/${d.id}/versions/${v.version}`);
    const prev = v.version > 1 ? await get<{ record: Record<string, unknown> }>(`/api/research/${d.id}/versions/${v.version - 1}`).catch(() => ({ record: {} })) : { record: {} };
    setDiff({ v: v.version, a: prev.record, b: cur.record, sections: v.diff?.changed_sections ?? [] });
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
      <div className="space-y-6">
        <Panel title="Comment">
          <Textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Leave a note for the reviewer" className="min-h-[80px]" aria-label="Comment" />
          <div className="mt-2 flex justify-end"><Button icon={<MessageSquare />} onClick={send} disabled={!comment.trim()}>Add comment</Button></div>
        </Panel>
        <Panel title="Activity">
          <ol>
            {(data?.events ?? []).map((e, i, arr) => (
              <li key={e.id} className="relative flex gap-3 pb-5">
                {i < arr.length - 1 && <span className="absolute top-4 bottom-0 left-[3.5px] w-px bg-[var(--border-default)]" aria-hidden />}
                <span className="relative mt-1.5 size-2 shrink-0 rounded-full" style={{ background: DOT[e.type] ?? "var(--g-400)" }} />
                <div className="min-w-0 flex-1 lg:flex lg:gap-4">
                  <div className="flex-1">
                    <p className={e.type === "comment" ? "rounded-md bg-subtle px-3 py-2 text-[14px]" : "text-[14px]"}>
                      {e.type === "comment" && e.user && <span className="font-semibold">{e.user.name}: </span>}{e.message}
                    </p>
                  </div>
                  <span className="shrink-0 text-caption text-fg-muted tabular" title={relative(e.created_at)}>{utc(e.created_at)}</span>
                </div>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
      <div className="space-y-6">
        <Panel title="Versions">
          <ul className="space-y-1">
            {(versions ?? []).map((v) => (
              <li key={`${v.version}-${v.changed_at}`}>
                <button onClick={() => viewDiff(v)} className="flex w-full items-center gap-2 rounded-sm px-2 py-2 text-left hover:bg-subtle">
                  <Badge>v{v.version}</Badge>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[14px]">{v.summary || "Updated"}</span>
                    <span className="text-caption text-fg-muted">{v.changed_by?.name ?? "System"} · {relative(v.changed_at)}</span>
                  </span>
                  <ChevronRight className="size-4 text-fg-muted" />
                </button>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Exports sent">
          {data?.exports.length ? (
            <ul className="space-y-2">
              {data.exports.map((x, i) => (
                <li key={i} className="flex items-center gap-2 text-[14px]">
                  <Avatar initials={x.user?.initials} size={20} />
                  <span className="flex-1 truncate">{x.file_name || x.format}</span>
                  <span className="text-caption text-fg-muted">{relative(x.created_at)}</span>
                </li>
              ))}
            </ul>
          ) : <p className="text-fg-muted">Nothing exported yet.</p>}
        </Panel>
      </div>
      <Dialog open={!!diff} onClose={() => setDiff(null)} size="lg" title={`Version ${diff?.v} changes`}>
        {diff && (
          <div className="space-y-4">
            {!diff.sections.length && <p className="text-fg-muted">First version — no earlier version to compare.</p>}
            {diff.sections.filter((s) => !s.startsWith("_") && s !== "review").map((s) => (
              <div key={s}>
                <h3 className="mb-1 text-h4 font-semibold">{s.replace(/_/g, " ")}</h3>
                <div className="grid gap-2 md:grid-cols-2">
                  <pre className="max-h-48 overflow-auto rounded-sm p-2 font-mono text-mono-sm whitespace-pre-wrap" style={{ background: "var(--danger-soft)" }}>{fmtVal(diff.a[s])}</pre>
                  <pre className="max-h-48 overflow-auto rounded-sm p-2 font-mono text-mono-sm whitespace-pre-wrap" style={{ background: "var(--success-soft)" }}>{fmtVal(diff.b[s])}</pre>
                </div>
              </div>
            ))}
          </div>
        )}
      </Dialog>
    </div>
  );
}

function fmtVal(v: unknown): string {
  if (v === undefined) return "—";
  if (typeof v === "string") return v;
  const s = JSON.stringify(v, null, 2);
  return s.length > 3000 ? s.slice(0, 3000) + "\n…" : s;
}
