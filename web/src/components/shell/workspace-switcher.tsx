"use client";

import clsx from "clsx";
import { Check, ChevronDown, Search, Settings2 } from "lucide-react";
import Link from "next/link";
import { useMemo, useRef, useState } from "react";
import { useApp } from "../providers";
import { Popover } from "../ui/overlay";

export function WorkspaceSwitcher() {
  const { workspaces, ws, activeWorkspace, setWs } = useApp();
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLDivElement | null>(null);
  const options = useMemo(() => {
    const all = [{ id: "all", name: "All workspaces", industry: "", color: "var(--g-400)" }, ...workspaces];
    return all.filter((w) => w.name.toLowerCase().includes(q.toLowerCase()));
  }, [workspaces, q]);

  return (
    <Popover align="start" width={320} label="Switch workspace" onOpenChange={(o) => { if (o) { setQ(""); setCursor(0); } }}
      trigger={(p) => (
        <button {...p} className="flex h-10 max-w-full min-w-0 items-center gap-2 rounded-sm px-2 text-left hover:bg-subtle" aria-label={`Workspace: ${activeWorkspace?.name ?? "All workspaces"}. Switch workspace`}>
          <span className="size-2 shrink-0 rounded-full" style={{ background: activeWorkspace?.color ?? "var(--g-400)" }} />
          <span className="min-w-0">
            <span className="block max-w-[180px] truncate text-[14px] leading-4 font-semibold">{activeWorkspace?.name ?? "All workspaces"}</span>
            <span className="block truncate text-caption text-fg-muted">{activeWorkspace?.industry ?? `${workspaces.length} clients`}</span>
          </span>
          <ChevronDown className="size-4 shrink-0 text-fg-muted" />
        </button>
      )}>
      {(close) => (
        <div className="p-2" onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setCursor((c) => Math.min(options.length - 1, c + 1)); }
          if (e.key === "ArrowUp") { e.preventDefault(); setCursor((c) => Math.max(0, c - 1)); }
          if (e.key === "Enter" && options[cursor]) { setWs(options[cursor].id); close(); }
        }}>
          <div className="relative mb-2">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-fg-muted" />
            <input autoFocus value={q} onChange={(e) => { setQ(e.target.value); setCursor(0); }} placeholder="Find workspace"
              className="h-8 w-full rounded-sm border border-line-strong bg-surface pr-2 pl-8 text-[14px] outline-none focus:border-accent" />
          </div>
          <div ref={listRef} role="listbox" aria-label="Workspaces" className="max-h-[320px] overflow-y-auto">
            {options.map((w, i) => (
              <div key={w.id}>
                <button role="option" aria-selected={w.id === ws} onMouseEnter={() => setCursor(i)} onClick={() => { setWs(w.id); close(); }}
                  className={clsx("flex h-9 w-full items-center gap-2 rounded-sm px-2 text-left text-[14px]", i === cursor && "bg-subtle")}>
                  <span className="grid w-4 place-items-center">{w.id === ws && <Check className="size-4 text-accent-text" />}</span>
                  <span className="size-2 shrink-0 rounded-full" style={{ background: w.color }} />
                  <span className="flex-1 truncate">{w.name}</span>
                  <span className="text-caption text-fg-muted">{w.industry}</span>
                </button>
                {w.id === "all" && options.length > 1 && <div className="my-1 h-px bg-[var(--border-subtle)]" />}
              </div>
            ))}
          </div>
          <div className="mt-1 border-t border-line pt-1">
            <Link href="/settings/workspaces" onClick={close} className="flex h-9 items-center gap-2 rounded-sm px-2 text-[14px] text-accent-text hover:bg-accent-soft">
              <Settings2 className="size-4" /> Manage workspaces
            </Link>
          </div>
        </div>
      )}
    </Popover>
  );
}
