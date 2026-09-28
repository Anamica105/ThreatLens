"use client";

import clsx from "clsx";
import { ArrowRight, Bug, Code, Download, Files, Fingerprint, LayoutDashboard, Plus, Search, UserRoundSearch, Building2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { get } from "@/lib/api";
import { useDebounced } from "@/lib/hooks";
import { useApp, useWsHref } from "../providers";
import { Kbd } from "../ui/badges";

interface Item { id: string; label: string; sub?: string; icon: React.ReactNode; run: () => void; group: string }

const RECENT_KEY = "tl.recent";

function recent(): { label: string; href: string }[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
  } catch {
    return [];
  }
}
export function pushRecent(label: string, href: string) {
  try {
    const xs = [{ label, href }, ...recent().filter((r) => r.href !== href)].slice(0, 6);
    localStorage.setItem(RECENT_KEY, JSON.stringify(xs));
  } catch {
    /* ignore */
  }
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void; inputRef?: React.RefObject<HTMLInputElement | null> }) {
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const [results, setResults] = useState<{ groups: { label: string; items: { id: string; title: string; sub: string; href: string }[] }[]; jump: { href: string } | null }>({ groups: [], jump: null });
  const debounced = useDebounced(q, 200);
  const router = useRouter();
  const wsHref = useWsHref();
  const { workspaces, setWs } = useApp();
  const input = useRef<HTMLInputElement | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setCursor(0);
      setTimeout(() => input.current?.focus(), 0);
    }
  }, [open]);

  useEffect(() => {
    if (!debounced.trim()) {
      setResults({ groups: [], jump: null });
      return;
    }
    let live = true;
    get<typeof results>(`/api/search?q=${encodeURIComponent(debounced)}`).then((r) => live && setResults(r)).catch(() => undefined);
    return () => { live = false; };
  }, [debounced]);

  const go = (href: string, label?: string) => {
    if (label) pushRecent(label, href);
    onClose();
    router.push(wsHref(href));
  };

  const items: Item[] = useMemo(() => {
    const out: Item[] = [];
    const ql = q.trim().toLowerCase();
    if (!ql) {
      recent().forEach((r, i) => out.push({ id: `recent-${i}`, label: r.label, icon: <ArrowRight />, run: () => go(r.href), group: "Recent" }));
    }
    for (const g of results.groups) {
      const icon = { Research: <Files />, "Threat actors": <UserRoundSearch />, "Malware & tools": <Bug />, IoCs: <Fingerprint />, Queries: <Code /> }[g.label] ?? <Search />;
      g.items.forEach((it) => out.push({ id: `${g.label}-${it.id}`, label: it.title, sub: it.sub, icon, run: () => go(it.href, it.title), group: g.label }));
    }
    const actions: Item[] = [
      { id: "a-new", label: "Start research", icon: <Plus />, run: () => go("/research/new"), group: "Actions" },
      { id: "a-dash", label: "Go to dashboard", icon: <LayoutDashboard />, run: () => go("/dashboard"), group: "Actions" },
      { id: "a-exp", label: "Export this week", icon: <Download />, run: () => go("/exports?period=week"), group: "Actions" },
      { id: "ws-all", label: "Switch workspace: All workspaces", icon: <Building2 />, run: () => { setWs("all"); onClose(); }, group: "Actions" },
      ...workspaces.map((w) => ({ id: `ws-${w.id}`, label: `Switch workspace: ${w.name}`, sub: w.industry, icon: <span className="size-2 rounded-full" style={{ background: w.color }} />, run: () => { setWs(w.id); onClose(); }, group: "Actions" })),
    ];
    const wsQuery = ql.startsWith("ws") ? ql.slice(2).trim() : ql;
    out.push(...actions.filter((a) => !ql || a.label.toLowerCase().includes(wsQuery) || (ql.startsWith("ws") && a.id.startsWith("ws"))));
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, results, workspaces]);

  useEffect(() => setCursor(0), [items.length]);
  useEffect(() => {
    panel.current?.querySelector(`[data-idx="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  if (!open || typeof document === "undefined") return null;
  const groups = Array.from(new Set(items.map((i) => i.group)));
  let idx = -1;
  return createPortal(
    <div className="fixed inset-0 z-[1200] flex items-start justify-center p-4 pt-[12vh]" style={{ background: "var(--scrim)" }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="w-full max-w-[640px] overflow-hidden rounded-lg border border-line bg-raised shadow-elev-3"
        onKeyDown={(e) => {
          if (e.key === "Escape") onClose();
          else if (e.key === "ArrowDown") { e.preventDefault(); setCursor((c) => Math.min(items.length - 1, c + 1)); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setCursor((c) => Math.max(0, c - 1)); }
          else if (e.key === "Enter") {
            e.preventDefault();
            if (results.jump && cursor === 0 && q.trim()) go(results.jump.href, q.trim());
            else items[cursor]?.run();
          }
        }}>
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="size-5 text-fg-muted" />
          <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search research, IoCs, actors… or type a command"
            className="h-14 flex-1 bg-transparent text-[16px] outline-none placeholder:text-fg-faint" aria-label="Search" />
          <Kbd>Esc</Kbd>
        </div>
        {results.jump && q.trim() && (
          <button onClick={() => go(results.jump!.href, q.trim())} className="flex w-full items-center gap-2 border-b border-line bg-accent-soft px-4 py-2.5 text-left text-[14px] text-accent-text">
            <ArrowRight className="size-4" /> Jump straight to <span className="font-mono">{q.trim()}</span>
          </button>
        )}
        <div ref={panel} className="max-h-[420px] overflow-y-auto p-2">
          {groups.map((g) => (
            <div key={g} className="mb-1">
              <div className="px-2 pt-2 pb-1 text-caption font-semibold text-fg-muted">{g}</div>
              {items.filter((i) => i.group === g).map((it) => {
                idx += 1;
                const my = idx;
                return (
                  <button key={it.id} data-idx={my} onMouseEnter={() => setCursor(my)} onClick={it.run}
                    className={clsx("flex h-10 w-full items-center gap-3 rounded-sm px-2 text-left [&_svg]:size-4", my === cursor ? "bg-subtle" : "")}>
                    <span className="grid w-4 place-items-center text-fg-muted">{it.icon}</span>
                    <span className="min-w-0 flex-1 truncate text-[14px]">{it.label}</span>
                    {it.sub && <span className="max-w-[40%] truncate text-caption text-fg-muted">{it.sub}</span>}
                  </button>
                );
              })}
            </div>
          ))}
          {!items.length && <p className="px-2 py-6 text-center text-fg-muted">No matches for &apos;{q}&apos;</p>}
        </div>
      </div>
    </div>,
    document.body,
  );
}
