"use client";

import clsx from "clsx";
import { useMemo, useRef, useState } from "react";
import type { User } from "@/lib/types";
import { useApp } from "../../providers";
import { Avatar } from "../../ui/badges";
import { Textarea } from "../../ui/forms";
import { mentionParts } from "./model";

/** Users mentioned in a message ("@Name" or "@id"). */
export function mentionedIds(message: string, users: User[]): string[] {
  return [...new Set(mentionParts(message, users).filter((p) => p.user).map((p) => p.user!.id))];
}

/** Textarea with @mention autocomplete over the workspace users (GET /api/meta users). Ctrl/Cmd+Enter submits. */
export function MentionInput({ value, onChange, onSubmit, placeholder, label, autoFocus, className }: {
  value: string; onChange: (v: string) => void; onSubmit?: () => void; placeholder?: string; label: string; autoFocus?: boolean; className?: string;
}) {
  const { meta } = useApp();
  const users = useMemo(() => meta?.users ?? [], [meta]);
  const ref = useRef<HTMLTextAreaElement | null>(null);
  const [query, setQuery] = useState<{ q: string; start: number } | null>(null);
  const [hi, setHi] = useState(0);

  const matches = useMemo(() => {
    if (!query) return [];
    const q = query.q.toLowerCase();
    return users.filter((u) => u.name.toLowerCase().includes(q) || u.id.toLowerCase().startsWith(q) || u.initials.toLowerCase() === q).slice(0, 6);
  }, [query, users]);

  const detect = (text: string, caret: number) => {
    const m = /(^|\s)@([\w.\- ]{0,24})$/.exec(text.slice(0, caret));
    if (m && !/\s{2}|\s$/.test(m[2]) || m && m[2] === "") {
      setQuery({ q: m![2], start: caret - m![2].length - 1 });
      setHi(0);
    } else setQuery(null);
  };

  const pick = (u: User) => {
    if (!query || !ref.current) return;
    const caret = ref.current.selectionStart ?? value.length;
    const next = `${value.slice(0, query.start)}@${u.name} ${value.slice(caret)}`;
    onChange(next);
    setQuery(null);
    const pos = query.start + u.name.length + 2;
    requestAnimationFrame(() => { ref.current?.focus(); ref.current?.setSelectionRange(pos, pos); });
  };

  const open = !!query && matches.length > 0;
  return (
    <div className={clsx("relative", className)}>
      <Textarea ref={ref} value={value} aria-label={label} placeholder={placeholder} autoFocus={autoFocus} autoGrow
        className="min-h-[72px]" role="combobox" aria-expanded={open} aria-autocomplete="list" aria-controls="mention-list"
        onChange={(e) => { onChange(e.target.value); detect(e.target.value, e.target.selectionStart ?? e.target.value.length); }}
        onBlur={() => setTimeout(() => setQuery(null), 120)}
        onKeyDown={(e) => {
          if (open) {
            if (e.key === "ArrowDown") { e.preventDefault(); setHi((h) => (h + 1) % matches.length); return; }
            if (e.key === "ArrowUp") { e.preventDefault(); setHi((h) => (h - 1 + matches.length) % matches.length); return; }
            if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); pick(matches[hi]); return; }
            if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setQuery(null); return; }
          }
          if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); onSubmit?.(); }
        }} />
      {open && (
        <ul id="mention-list" role="listbox" aria-label="Mention a teammate"
          className="absolute left-0 z-10 mt-1 w-64 rounded-md border border-line bg-raised p-1 shadow-elev-2">
          {matches.map((u, i) => (
            <li key={u.id} role="option" aria-selected={i === hi}>
              <button type="button" onMouseDown={(e) => { e.preventDefault(); pick(u); }} onMouseEnter={() => setHi(i)}
                className={clsx("flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-[14px]", i === hi && "bg-subtle")}>
                <Avatar initials={u.initials} size={20} />
                <span className="flex-1 truncate">{u.name}</span>
                <span className="text-caption text-fg-muted">{u.role}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** A comment body with @mentions highlighted. */
export function MentionText({ message }: { message: string }) {
  const { meta } = useApp();
  const parts = useMemo(() => mentionParts(message, meta?.users ?? []), [message, meta]);
  return (
    <p className="text-[14px] break-words whitespace-pre-wrap">
      {parts.map((p, i) => p.user
        ? <span key={i} className="rounded-sm bg-accent-soft px-0.5 font-semibold text-accent-text" title={p.user.email}>{p.text}</span>
        : <span key={i}>{p.text}</span>)}
    </p>
  );
}
