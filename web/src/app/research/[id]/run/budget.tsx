"use client";

import { OctagonAlert, TriangleAlert } from "lucide-react";

/** `budget` on GET /api/runs/{id} (spec §12: wall-clock and token budget per research depth). */
export interface RunBudget {
  depth: string; max_minutes: number; max_tokens: number; elapsed_minutes: number; tokens: number;
  pct_time: number; pct_tokens: number; state: "ok" | "warning" | "over"; enforced: boolean;
  /** Worst state reached and logged while the run executed (null when never past the warning line). */
  flagged: "warning" | "over" | null; stopped: boolean;
}

const WARN_PCT = 80;
const tone = (pct: number) => (pct > 100 ? "over" : pct >= WARN_PCT ? "warning" : "ok");
const COLOR = { ok: "var(--g-500)", warning: "var(--warning)", over: "var(--danger)" } as const;
const fmtMin = (m: number) => (m < 10 ? m.toFixed(1).replace(/\.0$/, "") : Math.round(m).toString());

function Bar({ label, used, max, pct, unit }: { label: string; used: string; max: string; pct: number; unit: string }) {
  const t = tone(pct);
  return (
    <div className="min-w-0">
      <div className="mb-1 flex items-baseline justify-between gap-2 text-caption">
        <span className="font-semibold text-fg-strong">{label}</span>
        <span className="tabular truncate text-fg-muted">
          {used} of {max} {unit} · <span className="font-semibold" style={{ color: t === "ok" ? undefined : COLOR[t] }}>{Math.round(pct)}%</span>
        </span>
      </div>
      <div className="relative h-1.5 overflow-hidden rounded-full bg-[var(--g-100)] dark:bg-[#2E3440]" role="progressbar"
        aria-label={`${label} budget`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(Math.min(pct, 100))} aria-valuetext={`${Math.round(pct)}% of ${label.toLowerCase()} budget`}>
        <div className="h-full rounded-full transition-[width]" style={{ width: `${Math.min(100, Math.max(0, pct))}%`, background: COLOR[t] }} />
        <span className="absolute top-0 bottom-0 w-px bg-[var(--g-400)]" style={{ left: `${WARN_PCT}%` }} aria-hidden />
      </div>
    </div>
  );
}

/** Two-bar budget meter (time, tokens): neutral below 80%, amber from 80%, red when over. */
export function BudgetMeter({ budget, running }: { budget: RunBudget; running: boolean }) {
  const b = budget;
  const note = b.stopped
    ? { icon: <OctagonAlert className="size-4 shrink-0" />, color: COLOR.over, text: "Run stopped: it went over its budget and budget enforcement is on." }
    : b.state === "over" || b.flagged === "over"
      ? { icon: <OctagonAlert className="size-4 shrink-0" />, color: COLOR.over, text: `Over the ${b.depth} budget${b.enforced ? "" : "; budget is advisory, so the run was not stopped"}.` }
      : b.state === "warning" || b.flagged === "warning"
        ? { icon: <TriangleAlert className="size-4 shrink-0" />, color: COLOR.warning, text: `Past ${WARN_PCT}% of the ${b.depth} budget${running && b.enforced ? "; the run stops at the next stage if it goes over" : ""}.` }
        : null;
  return (
    <section aria-label="Run budget" className="mt-4 max-w-xl space-y-2">
      <div className="grid gap-3 sm:grid-cols-2">
        <Bar label="Time" used={fmtMin(b.elapsed_minutes)} max={fmtMin(b.max_minutes)} unit="min" pct={b.pct_time} />
        <Bar label="Tokens" used={b.tokens.toLocaleString()} max={b.max_tokens.toLocaleString()} unit="tokens" pct={b.pct_tokens} />
      </div>
      <p className="text-caption text-fg-muted">
        Budget for <span className="font-semibold">{b.depth}</span> depth · {b.enforced ? "enforced (the run stops when over)" : "advisory (not enforced)"}
      </p>
      {note && <p className="flex items-start gap-1.5 text-body-sm font-semibold" style={{ color: note.color }}>{note.icon}{note.text}</p>}
    </section>
  );
}
