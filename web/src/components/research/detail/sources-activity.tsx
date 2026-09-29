"use client";

import { ArrowRight, ChevronRight, GitCompare, MessageSquare } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { post } from "@/lib/api";
import { useApp } from "../../providers";
import { MentionInput, MentionText, mentionedIds } from "../comments/mention-input";
import { sectionLabel, threadHref, useComments, type CommentThread } from "../comments/model";
import { relative, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { User } from "@/lib/types";
import { Avatar, Badge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { Alert, useToast } from "../../ui/feedback";
import { Select } from "../../ui/forms";
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

/** GET /api/research/{id}/diff */
interface WordOp { op: "eq" | "add" | "del"; text: string }
interface FieldChange { field: string; before: string; after: string; ops: WordOp[] }
interface DiffItem { index: number; label: string; item?: unknown }
interface DiffSection {
  section: string; label: string; kind: "list" | "object" | "text"; summary: string;
  added?: DiffItem[]; removed?: DiffItem[]; changed?: (DiffItem & { fields: FieldChange[] })[];
  fields?: FieldChange[]; before?: string; after?: string; ops?: WordOp[]; count_before?: number; count_after?: number;
}
interface DiffResponse { from: number; to: number; sections: DiffSection[]; summary: string }

const DOT: Record<string, string> = { created: "var(--accent)", run_completed: "var(--accent)", status: "var(--success)", edited: "var(--info)", exported: "var(--g-400)", result: "var(--sev-medium)", comment: "var(--text-secondary)", comment_status: "var(--success)" };

export function ActivityTab({ d }: DetailProps) {
  const { meta } = useApp();
  const { data, reload } = useApi<Activity>(`/api/research/${d.id}/activity`);
  const { data: versions } = useApi<Version[]>(`/api/research/${d.id}/versions`);
  const comments = useComments(d.id);
  const [comment, setComment] = useState("");
  const [cmp, setCmp] = useState<{ from: number; to: number } | null>(null);
  const toast = useToast();

  // Version numbers can have gaps (older records); the picker offers the stored snapshots plus the current version.
  const nums = useMemo(() => [...new Set([d.version, ...(versions ?? []).map((v) => v.version)])].sort((a, b) => b - a), [versions, d.version]);
  const [pick, setPick] = useState<{ from: string; to: string }>({ from: "", to: "" });
  const pickFrom = pick.from || String(nums[1] ?? nums[0] ?? "");
  const pickTo = pick.to || String(nums[0] ?? "");

  const send = async () => {
    if (!comment.trim()) return;
    await post(`/api/research/${d.id}/comments`, { message: comment, mentions: mentionedIds(comment, meta?.users ?? []) });
    setComment("");
    toast({ tone: "success", message: "Comment added" });
    reload();
    comments.reload();
  };
  const viewDiff = (v: Version) => {
    const prev = nums.find((n) => n < v.version);
    setCmp({ from: prev ?? 0, to: v.version });
  };
  const bySection = useMemo(() => {
    const m = new Map<string, CommentThread[]>();
    for (const t of comments.data?.threads ?? []) m.set(t.section ?? "", [...(m.get(t.section ?? "") ?? []), t]);
    return [...m.entries()];
  }, [comments.data]);

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
      <div className="space-y-6">
        <Panel title="Comment">
          <MentionInput value={comment} onChange={setComment} onSubmit={send} label="Comment" placeholder="Leave a note for the reviewer… type @ to mention" />
          <div className="mt-2 flex justify-end"><Button icon={<MessageSquare />} onClick={send} disabled={!comment.trim()}>Add comment</Button></div>
        </Panel>
        <Panel title="Comments by section">
          {bySection.length ? (
            <ul className="divide-y divide-[var(--border-default)]">
              {bySection.map(([sec, threads]) => {
                const open = threads.filter((t) => !t.resolved).length;
                const last = threads.flatMap((t) => [t, ...t.replies]).sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
                return (
                  <li key={sec || "general"} className="flex items-start gap-3 py-2.5">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[14px] font-semibold">{sectionLabel(sec || null)}</span>
                        <Badge tone={open ? "accent" : "neutral"}>{open ? `${open} open` : "resolved"}</Badge>
                        <span className="text-caption text-fg-muted">{threads.length} thread{threads.length === 1 ? "" : "s"}</span>
                      </div>
                      {last && <p className="mt-0.5 truncate text-body-sm text-fg-strong"><span className="font-semibold">{last.user?.name}: </span>{last.message}</p>}
                    </div>
                    {sec
                      ? <Link href={threadHref(d.id, sec, last?.id)} className="inline-flex shrink-0 items-center gap-1 text-[14px] font-semibold text-accent-text hover:underline">Open <ArrowRight className="size-4" /></Link>
                      : null}
                  </li>
                );
              })}
            </ul>
          ) : <p className="text-fg-muted">No comments yet. Use the comment icon on any report section heading to start a thread.</p>}
        </Panel>
        <Panel title="Activity">
          <ol>
            {(data?.events ?? []).map((e, i, arr) => {
              const sec = typeof e.meta?.section === "string" ? e.meta.section : null;
              const isReply = !!e.meta?.parent_id;
              return (
                <li key={e.id} className="relative flex gap-3 pb-5">
                  {i < arr.length - 1 && <span className="absolute top-4 bottom-0 left-[3.5px] w-px bg-[var(--border-default)]" aria-hidden />}
                  <span className="relative mt-1.5 size-2 shrink-0 rounded-full" style={{ background: DOT[e.type] ?? "var(--g-400)" }} />
                  <div className="min-w-0 flex-1 lg:flex lg:gap-4">
                    <div className="min-w-0 flex-1">
                      {e.type === "comment" ? (
                        <div className="rounded-md bg-subtle px-3 py-2">
                          <div className="mb-0.5 flex flex-wrap items-center gap-x-2 text-caption text-fg-muted">
                            <span className="font-semibold text-fg">{e.user?.name ?? "Someone"}</span>
                            <span>{isReply ? "replied on" : "commented on"}</span>
                            {sec ? <Link href={threadHref(d.id, sec, e.id)} className="font-semibold text-accent-text hover:underline">{sectionLabel(sec)}</Link> : <span>the report</span>}
                          </div>
                          <MentionText message={e.message} />
                        </div>
                      ) : (
                        <p className="text-[14px]">
                          {e.message}
                          {e.type === "comment_status" && sec && <> · <Link href={threadHref(d.id, sec)} className="font-semibold text-accent-text hover:underline">View thread</Link></>}
                        </p>
                      )}
                    </div>
                    <span className="shrink-0 text-caption text-fg-muted tabular" title={relative(e.created_at)}>{utc(e.created_at)}</span>
                  </div>
                </li>
              );
            })}
          </ol>
        </Panel>
      </div>
      <div className="space-y-6">
        <Panel title="Versions">
          {nums.length > 1 && (
            <div className="mb-3 rounded-md border border-line p-3">
              <div className="mb-2 text-caption font-semibold text-fg-muted">Compare versions</div>
              <div className="flex items-center gap-2">
                <Select size="sm" className="flex-1" ariaLabel="From version" value={pickFrom} onChange={(v) => setPick((p) => ({ ...p, from: v }))}
                  options={nums.map((n) => ({ value: String(n), label: `v${n}${n === d.version ? " · current" : ""}` }))} />
                <ArrowRight className="size-4 shrink-0 text-fg-muted" aria-hidden />
                <Select size="sm" className="flex-1" ariaLabel="To version" value={pickTo} onChange={(v) => setPick((p) => ({ ...p, to: v }))}
                  options={nums.map((n) => ({ value: String(n), label: `v${n}${n === d.version ? " · current" : ""}` }))} />
                </div>
              <div className="mt-2 flex justify-end">
                <Button size="sm" icon={<GitCompare />} disabled={pickFrom === pickTo} onClick={() => setCmp({ from: Number(pickFrom), to: Number(pickTo) })}>Compare</Button>
              </div>
            </div>
          )}
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
      {cmp && <DiffDialog rid={d.id} from={cmp.from} to={cmp.to} onClose={() => setCmp(null)} />}
    </div>
  );
}

function Ops({ ops }: { ops: WordOp[] }) {
  return (
    <span className="whitespace-pre-wrap break-words">
      {ops.map((o, i) => o.op === "eq" ? <span key={i}>{o.text}</span>
        : o.op === "add" ? <ins key={i} className="rounded-sm no-underline" style={{ background: "var(--success-soft)" }}>{o.text}</ins>
          : <del key={i} className="rounded-sm text-fg-muted" style={{ background: "var(--danger-soft)" }}>{o.text}</del>)}
    </span>
  );
}

function Fields({ fields }: { fields: FieldChange[] }) {
  return (
    <dl className="mt-1 space-y-1">
      {fields.map((f) => (
        <div key={f.field} className="grid grid-cols-[110px_minmax(0,1fr)] gap-2 text-body-sm">
          <dt className="text-fg-muted">{f.field.replace(/_/g, " ")}</dt>
          <dd className="max-h-40 overflow-auto"><Ops ops={f.ops} /></dd>
        </div>
      ))}
    </dl>
  );
}

function DiffDialog({ rid, from, to, onClose }: { rid: string; from: number; to: number; onClose: () => void }) {
  const { data, error } = useApi<DiffResponse>(`/api/research/${rid}/diff?from=${from}&to=${to}`);
  return (
    <Dialog open onClose={onClose} size="lg" title={from ? `Changes v${from} → v${to}` : `Version ${to}`}>
      {error && <Alert tone="danger" title="Could not compare versions">{error.message}</Alert>}
      {!data && !error && <p className="text-fg-muted">Comparing…</p>}
      {data && (
        <div className="space-y-5">
          {!from && <p className="text-fg-muted">No earlier stored version — showing everything in v{to} as added.</p>}
          {data.sections.length === 0 && <p className="text-fg-muted">No differences between these versions.</p>}
          {data.sections.length > 0 && (
            <ul className="flex flex-wrap gap-1.5" aria-label="Summary">
              {data.sections.map((s, i) => <li key={i}><a href={`#diff-${s.section}-${i}`} className="inline-flex rounded-sm bg-subtle px-2 py-1 text-caption hover:underline"><span className="font-semibold">{s.label}</span>&nbsp;· {s.summary}</a></li>)}
            </ul>
          )}
          {data.sections.map((s, i) => (
            <section key={i} id={`diff-${s.section}-${i}`} className="border-t border-line pt-3">
              <h3 className="mb-2 flex flex-wrap items-baseline gap-2 text-h4 font-semibold">
                {s.label}<span className="text-body-sm font-normal text-fg-muted">{s.summary}</span>
                {s.kind === "list" && s.count_before !== undefined && <span className="ml-auto text-caption font-normal text-fg-muted tabular">{s.count_before} → {s.count_after}</span>}
              </h3>
              {s.kind === "text" && s.ops && <div className="max-h-60 overflow-auto rounded-sm bg-subtle p-2 text-body-sm"><Ops ops={s.ops} /></div>}
              {s.kind === "object" && s.fields && <Fields fields={s.fields} />}
              {s.kind === "list" && (
                <ul className="space-y-1.5 text-body-sm">
                  {s.added?.map((x) => (
                    <li key={`a${x.index}-${x.label}`} className="flex gap-2 rounded-sm px-2 py-1" style={{ background: "var(--success-soft)" }}>
                      <span className="font-mono font-semibold text-success" aria-label="Added">+</span><span className="min-w-0 break-words">{x.label}</span>
                    </li>
                  ))}
                  {s.removed?.map((x) => (
                    <li key={`r${x.index}-${x.label}`} className="flex gap-2 rounded-sm px-2 py-1" style={{ background: "var(--danger-soft)" }}>
                      <span className="font-mono font-semibold text-danger" aria-label="Removed">−</span><span className="min-w-0 break-words line-through decoration-1">{x.label}</span>
                    </li>
                  ))}
                  {s.changed?.map((x) => (
                    <li key={`c${x.index}-${x.label}`} className="rounded-sm border border-line px-2 py-1.5">
                      <div className="flex gap-2"><span className="font-mono font-semibold text-info" aria-label="Changed">~</span><span className="min-w-0 font-semibold break-words">#{x.index} {x.label}</span></div>
                      <Fields fields={x.fields} />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}
        </div>
      )}
    </Dialog>
  );
}
