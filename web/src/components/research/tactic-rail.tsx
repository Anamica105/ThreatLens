"use client";

import clsx from "clsx";
import type { Tactic } from "@/lib/types";
import { Tooltip } from "../ui/overlay";

export function railFill(n: number) {
  if (n <= 0) return "var(--rail-0)";
  if (n === 1) return "var(--rail-1)";
  if (n <= 3) return "var(--rail-2)";
  return "var(--rail-4)";
}

/**
 * The ATT&CK tactic rail — the product's one signature element (design.md 18.1).
 * Tactic names/order always come from the API (synced ATT&CK), never hard-coded here.
 */
export function TacticRail({ tactics, variant = "header", onSelect, selected, animate }:
  { tactics: Tactic[]; variant?: "header" | "mini"; onSelect?: (tacticId: string | null) => void; selected?: string | null; animate?: boolean }) {
  const lit = tactics.filter((t) => (t.count ?? 0) > 0);
  const summary = lit.length
    ? `ATT&CK tactics covered: ${lit.map((t) => `${t.name} (${t.count} technique${t.count === 1 ? "" : "s"})`).join(", ")}`
    : "No ATT&CK tactics mapped";
  if (variant === "mini") {
    return (
      <Tooltip content={lit.length ? lit.map((t) => t.name).join(", ") : "No tactics mapped"}>
        <div role="img" aria-label={summary} className="grid grid-cols-14 gap-[2px]" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0,1fr))` }}>
          {tactics.map((t) => <div key={t.id} className="h-1.5 rounded-xs" style={{ background: railFill(t.count ?? 0) }} />)}
        </div>
      </Tooltip>
    );
  }
  return (
    <div aria-label={summary} role="list" className="grid gap-[3px]" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0,1fr))` }}>
      {tactics.map((t, i) => {
        const n = t.count ?? 0;
        const isSel = selected === t.id;
        const seg = (
          <button type="button" role="listitem" aria-hidden={n === 0} tabIndex={onSelect && n ? 0 : -1}
            aria-label={n ? `${t.name}: ${n} technique${n === 1 ? "" : "s"}${isSel ? " (filtered)" : ""}` : undefined}
            onClick={() => onSelect && n && onSelect(isSel ? null : t.id)}
            className={clsx("group flex min-w-0 flex-col items-center gap-1", onSelect && n ? "cursor-pointer" : "cursor-default")}>
            <span className={clsx("block h-2.5 w-full rounded-xs", animate && n > 0 && "rail-light", isSel && "outline outline-2 outline-offset-1 outline-[var(--focus-ring)]")}
              style={{ background: railFill(n), animationDelay: animate ? `${i * 40}ms` : undefined }} />
            <span className={clsx("w-full truncate text-center text-[11px] leading-3 sm:text-caption", n ? "text-fg-muted" : "text-fg-faint", isSel && "font-semibold text-fg")}>{t.short}</span>
          </button>
        );
        return <Tooltip key={t.id} content={`${t.name} · ${n} technique${n === 1 ? "" : "s"}`}>{seg}</Tooltip>;
      })}
    </div>
  );
}
