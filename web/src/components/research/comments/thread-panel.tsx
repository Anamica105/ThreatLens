"use client";

import clsx from "clsx";
import { CheckCircle2, MessageSquare, RotateCcw } from "lucide-react";
import { useEffect, useState } from "react";
import { post } from "@/lib/api";
import { relative, utc } from "@/lib/format";
import { Avatar, Badge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { useToast } from "../../ui/feedback";
import { Drawer } from "../../ui/overlay";
import { MentionInput, MentionText, mentionedIds } from "./mention-input";
import { sectionLabel, type CommentItem, type CommentThread, type CommentsResponse, type SectionCount } from "./model";
import { useApp } from "../../providers";

/** Comment icon + open-thread count for a report section header. */
export function CommentButton({ count, onClick, label }: { count?: SectionCount; onClick: () => void; label: string }) {
  const open = count?.open ?? 0;
  const total = count?.comments ?? 0;
  return (
    <button type="button" onClick={onClick} data-comment-section={label}
      aria-label={total ? `${total} comment${total === 1 ? "" : "s"} on ${label}${open ? `, ${open} open` : ""}` : `Comment on ${label}`}
      title={total ? `${open} open thread${open === 1 ? "" : "s"} · ${total} comment${total === 1 ? "" : "s"}` : "Comment on this section"}
      className={clsx("inline-flex h-7 items-center gap-1 rounded-sm px-1.5 text-[13px] hover:bg-subtle",
        open ? "font-semibold text-accent-text" : "text-fg-muted")}>
      <MessageSquare className="size-4" />
      {total > 0 && <span className="tabular">{open || total}</span>}
    </button>
  );
}

function Comment({ c, compact }: { c: CommentItem; compact?: boolean }) {
  return (
    <div id={`comment-${c.id}`} className={clsx("flex gap-2.5", compact && "mt-3")}>
      <Avatar initials={c.user?.initials} size={compact ? 20 : 24} title={c.user?.name} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-[14px] font-semibold">{c.user?.name ?? "Someone"}</span>
          <span className="text-caption text-fg-muted" title={utc(c.created_at)}>{relative(c.created_at)}</span>
        </div>
        <MentionText message={c.message} />
      </div>
    </div>
  );
}

function Thread({ rid, t, onChanged, highlight }: { rid: string; t: CommentThread; onChanged: () => Promise<void>; highlight?: boolean }) {
  const { meta } = useApp();
  const toast = useToast();
  const [reply, setReply] = useState("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const send = async () => {
    if (!reply.trim()) return;
    setBusy(true);
    try {
      await post(`/api/research/${rid}/comments`, { message: reply, parent_id: t.id, mentions: mentionedIds(reply, meta?.users ?? []) });
      setReply("");
      setOpen(false);
      await onChanged();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };
  const resolve = async (resolved: boolean) => {
    try {
      await post(`/api/research/${rid}/comments/${t.id}/resolve`, { resolved });
      toast({ tone: "success", message: resolved ? "Thread resolved" : "Thread reopened" });
      await onChanged();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };
  return (
    <li className={clsx("rounded-md border p-3", t.resolved ? "border-line bg-subtle" : "border-line bg-surface", highlight && "ring-2 ring-[var(--accent)]")}
      data-thread={t.id}>
      <Comment c={t} />
      <div className="ml-[34px]">
        {t.replies.map((r) => <Comment key={r.id} c={r} compact />)}
        {t.resolved && <p className="mt-2 flex items-center gap-1 text-caption text-fg-muted"><CheckCircle2 className="size-3.5 text-success" />Resolved by {t.resolved_by?.name ?? "someone"}{t.resolved_at ? ` · ${relative(t.resolved_at)}` : ""}</p>}
        {open ? (
          <div className="mt-3">
            <MentionInput value={reply} onChange={setReply} onSubmit={send} label="Reply" placeholder="Reply… type @ to mention" autoFocus />
            <div className="mt-2 flex justify-end gap-2">
              <Button size="sm" variant="tertiary" onClick={() => { setOpen(false); setReply(""); }}>Cancel</Button>
              <Button size="sm" variant="primary" onClick={send} loading={busy} disabled={!reply.trim()}>Reply</Button>
            </div>
          </div>
        ) : (
          <div className="mt-2 flex gap-1">
            <Button size="sm" variant="tertiary" onClick={() => setOpen(true)}>Reply</Button>
            {t.resolved
              ? <Button size="sm" variant="tertiary" icon={<RotateCcw />} onClick={() => resolve(false)}>Reopen</Button>
              : <Button size="sm" variant="tertiary" icon={<CheckCircle2 />} onClick={() => resolve(true)}>Resolve</Button>}
          </div>
        )}
      </div>
    </li>
  );
}

/** Side drawer with the comment threads of one report section: new thread, reply, resolve / reopen. */
export function ThreadPanel({ rid, section, data, reload, onClose, focus }: {
  rid: string; section: string | null; data?: CommentsResponse; reload: () => Promise<void>; onClose: () => void; focus?: number | null;
}) {
  const { meta } = useApp();
  const toast = useToast();
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [showResolved, setShowResolved] = useState(false);
  const all = (data?.threads ?? []).filter((t) => (t.section ?? null) === section);
  const focusThread = focus ? all.find((t) => t.id === focus || t.replies.some((r) => r.id === focus))?.id : undefined;
  const resolved = all.filter((t) => t.resolved);
  const shown = all.filter((t) => !t.resolved || showResolved || t.id === focusThread);

  useEffect(() => {
    if (!focus) return;
    const t = setTimeout(() => document.getElementById(`comment-${focus}`)?.scrollIntoView({ block: "center" }), 80);
    return () => clearTimeout(t);
  }, [focus, data]);

  const send = async () => {
    if (!msg.trim()) return;
    setBusy(true);
    try {
      const r = await post<{ notified: string[] }>(`/api/research/${rid}/comments`, { message: msg, section, mentions: mentionedIds(msg, meta?.users ?? []) });
      setMsg("");
      const names = r.notified.map((id) => meta?.users.find((u) => u.id === id)?.name ?? id);
      toast({ tone: "success", message: names.length ? `Comment added · notified ${names.join(", ")}` : "Comment added" });
      await reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };

  return (
    <Drawer open onClose={onClose} width={440} title={`Comments · ${sectionLabel(section)}`}
      subtitle={`${all.length - resolved.length} open · ${resolved.length} resolved`}>
      <div className="space-y-4 p-5">
        <div>
          <MentionInput value={msg} onChange={setMsg} onSubmit={send} label={`New comment on ${sectionLabel(section)}`}
            placeholder="Start a thread… type @ to mention a teammate" />
          <div className="mt-2 flex items-center justify-between gap-2">
            <span className="text-caption text-fg-muted">Ctrl+Enter to post</span>
            <Button size="sm" variant="primary" icon={<MessageSquare />} onClick={send} loading={busy} disabled={!msg.trim()}>Comment</Button>
          </div>
        </div>
        {shown.length > 0 ? (
          <ul className="space-y-3">
            {shown.map((t) => <Thread key={t.id} rid={rid} t={t} onChanged={reload} highlight={t.id === focusThread} />)}
          </ul>
        ) : <p className="text-fg-muted">{all.length ? "All threads here are resolved." : "No comments on this section yet."}</p>}
        {resolved.length > 0 && (
          <button type="button" onClick={() => setShowResolved((v) => !v)} className="text-[14px] font-semibold text-accent-text hover:underline">
            {showResolved ? "Hide" : "Show"} {resolved.length} resolved thread{resolved.length === 1 ? "" : "s"} <Badge>{resolved.length}</Badge>
          </button>
        )}
      </div>
    </Drawer>
  );
}
