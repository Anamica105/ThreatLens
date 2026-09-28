"use client";

import clsx from "clsx";
import { Table2, ChartColumn } from "lucide-react";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis, LabelList } from "recharts";
import { num } from "@/lib/format";
import { Tooltip } from "./ui/overlay";

const AXIS = { fontSize: 12, fill: "var(--text-secondary)", fontFamily: "var(--font-sans)" };

function TipCard({ title, rows }: { title: string; rows: { label: string; value: string | number; color?: string }[] }) {
  return (
    <div className="rounded-md border border-line bg-raised px-3 py-2 shadow-elev-2">
      <div className="mb-1 text-caption font-semibold text-fg-muted">{title}</div>
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-2 text-[13px]">
          {r.color && <span className="size-2 rounded-[2px]" style={{ background: r.color }} />}
          <span className="flex-1 text-fg">{r.label}</span>
          <span className="font-semibold tabular text-fg">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

/** Chart frame with a "View as table" toggle so every chart has a text alternative. */
export function ChartFrame({ table, children, height = 220, empty }: { table: { head: string[]; rows: (string | number)[][] }; children: React.ReactNode; height?: number; empty?: boolean }) {
  const [asTable, setAsTable] = useState(false);
  return (
    <div className="relative">
      <div className="absolute -top-10 right-0">
        <Tooltip content={asTable ? "View as chart" : "View as table"}>
          <button onClick={() => setAsTable(!asTable)} aria-label={asTable ? "View as chart" : "View as table"} aria-pressed={asTable}
            className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-subtle">
            {asTable ? <ChartColumn className="size-4" /> : <Table2 className="size-4" />}
          </button>
        </Tooltip>
      </div>
      {asTable ? (
        <div className="overflow-auto" style={{ maxHeight: height }}>
          <table className="tl-table tl-compact w-full">
            <thead><tr>{table.head.map((h, i) => <th key={h} className={i ? "num" : ""}>{h}</th>)}</tr></thead>
            <tbody>{table.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className={j ? "num" : ""}>{c}</td>)}</tr>)}</tbody>
          </table>
        </div>
      ) : (
        <div style={{ height }} className="relative">
          {children}
          {empty && <div className="absolute inset-0 grid place-items-center text-fg-muted">No research in this period</div>}
        </div>
      )}
    </div>
  );
}

export function RunsLine({ data, onPoint }: { data: { week: string; count: number }[]; onPoint?: (week: string) => void }) {
  const fmt = (w: string) => new Date(w + "T00:00:00Z").toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
  const empty = data.every((d) => d.count === 0);
  return (
    <ChartFrame empty={empty} table={{ head: ["Week of", "Research runs"], rows: data.map((d) => [fmt(d.week), d.count]) }}>
      <ResponsiveContainer>
        <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -16 }}
          onClick={(e) => { const p = (e as { activeLabel?: string } | null)?.activeLabel; if (p && onPoint) onPoint(p); }}>
          <CartesianGrid vertical={false} stroke="var(--border-subtle)" />
          <XAxis dataKey="week" tickFormatter={fmt} tick={AXIS} axisLine={false} tickLine={false} minTickGap={24} />
          <YAxis allowDecimals={false} tick={AXIS} axisLine={false} tickLine={false} width={40} />
          <RTooltip cursor={{ stroke: "var(--border-default)" }} content={({ active, payload, label }) =>
            active && payload?.length ? <TipCard title={`Week of ${fmt(String(label))}`} rows={[{ label: "Research runs", value: num(Number(payload[0].value)), color: "var(--accent)" }]} /> : null} />
          <Line type="linear" dataKey="count" stroke="var(--accent)" strokeWidth={2} dot={false} activeDot={{ r: 5, stroke: "var(--bg-surface)", strokeWidth: 2 }} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Horizontal bar list with category labels on the axis and direct value labels (identity never by colour alone). */
export function CategoryBars({ data, onBar, unit = "research" }: { data: { key: string; label: string; count: number; color: string }[]; onBar?: (key: string) => void; unit?: string }) {
  const empty = data.every((d) => d.count === 0);
  return (
    <ChartFrame empty={empty} height={Math.max(160, data.length * 40)} table={{ head: ["Category", "Count"], rows: data.map((d) => [d.label, d.count]) }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 36, bottom: 0, left: 0 }} barCategoryGap={10}>
          <CartesianGrid horizontal={false} stroke="var(--border-subtle)" />
          <XAxis type="number" allowDecimals={false} tick={AXIS} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="label" tick={{ ...AXIS, fill: "var(--text-primary)" }} axisLine={false} tickLine={false} width={150} />
          <RTooltip cursor={{ fill: "var(--bg-subtle)" }} content={({ active, payload }) => {
            if (!active || !payload?.length) return null;
            const p = payload[0].payload as { label: string; count: number; color: string };
            return <TipCard title={p.label} rows={[{ label: unit, value: num(p.count), color: p.color }]} />;
          }} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={22} isAnimationActive={false} cursor={onBar ? "pointer" : undefined}
            onClick={(d) => onBar?.((d as unknown as { key: string }).key)}>
            {data.map((d) => <Cell key={d.key} fill={d.color} />)}
            <LabelList dataKey="count" position="right" style={{ fontSize: 12, fill: "var(--text-primary)", fontWeight: 600 }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

export function heatColor(n: number, max: number) {
  if (n <= 0) return "var(--heat-0)";
  const r = n / Math.max(1, max);
  if (r <= 0.25) return "var(--heat-2)";
  if (r <= 0.5) return "var(--heat-3)";
  if (r <= 0.8) return "var(--heat-4)";
  return "var(--heat-5)";
}

/** ATT&CK coverage heatmap: tactics as columns, techniques as cells, sequential ultraviolet ramp. */
export function AttackHeatmap({ tactics, onCell }: {
  tactics: { id: string; name: string; short: string; techniques: { id: string; name: string; count: number }[] }[];
  onCell?: (techniqueId: string) => void;
}) {
  const max = Math.max(1, ...tactics.flatMap((t) => t.techniques.map((c) => c.count)));
  const rows = Math.max(3, ...tactics.map((t) => t.techniques.length));
  const shown = Math.min(rows, 10);
  const table = { head: ["Tactic", "Technique", "Research"], rows: tactics.flatMap((t) => t.techniques.map((c) => [t.name, `${c.id} ${c.name}`, c.count])) };
  return (
    <ChartFrame height={shown * 30 + 40} table={table}>
      <div className="fade-x -mx-1 overflow-x-auto px-1 pb-1">
        <div className="grid min-w-[900px] gap-1" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0,1fr))` }}>
          {tactics.map((t) => (
            <div key={t.id} className="min-w-0">
              <Tooltip content={t.name}><div className="mb-1 truncate text-center text-caption font-semibold text-fg-muted">{t.short}</div></Tooltip>
              <div className="grid gap-1">
                {Array.from({ length: shown }).map((_, i) => {
                  const c = t.techniques[i];
                  if (!c) return <div key={i} className="h-[26px] rounded-xs border border-line" style={{ background: "var(--heat-0)" }} aria-hidden />;
                  const dark = c.count / max > 0.5;
                  return (
                    <Tooltip key={c.id} content={<span><span className="font-mono">{c.id}</span> {c.name}<br />{c.count} research</span>}>
                      <button onClick={() => onCell?.(c.id)} aria-label={`${c.id} ${c.name}: ${c.count} research`}
                        className={clsx("h-[26px] truncate rounded-xs px-1 font-mono text-[11px] font-semibold", dark ? "text-white" : "text-[var(--uv-900)]")}
                        style={{ background: heatColor(c.count, max) }}>
                        {c.id}
                      </button>
                    </Tooltip>
                  );
                })}
                {t.techniques.length > shown && <div className="text-center text-caption text-fg-muted">+{t.techniques.length - shown}</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-2 flex items-center gap-2 text-caption text-fg-muted">
        <span>Fewer</span>
        {["var(--heat-2)", "var(--heat-3)", "var(--heat-4)", "var(--heat-5)"].map((c) => <span key={c} className="h-2.5 w-6 rounded-xs" style={{ background: c }} />)}
        <span>More research</span>
      </div>
    </ChartFrame>
  );
}

export function RankedList({ items, onItem }: { items: { key: string; label: React.ReactNode; count: number; mono?: boolean }[]; onItem?: (key: string) => void }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  if (!items.length) return <p className="py-6 text-center text-fg-muted">No research in this period</p>;
  return (
    <ol className="space-y-1">
      {items.map((it, i) => (
        <li key={it.key}>
          <button onClick={() => onItem?.(it.key)} className="flex w-full items-center gap-3 rounded-sm px-1 py-1.5 text-left hover:bg-subtle">
            <span className="w-4 text-right tabular text-caption text-fg-muted">{i + 1}</span>
            <span className="min-w-0 flex-1">
              <span className={clsx("block truncate text-[14px] text-accent-text", it.mono && "font-mono text-mono")}>{it.label}</span>
              <span className="mt-1 block h-1 rounded-full bg-[var(--g-100)] dark:bg-[#2E3440]">
                <span className="block h-1 rounded-full bg-accent" style={{ width: `${(100 * it.count) / max}%` }} />
              </span>
            </span>
            <span className="w-8 text-right tabular text-[14px] font-semibold">{it.count}</span>
          </button>
        </li>
      ))}
    </ol>
  );
}

export function KpiTile({ label, value, delta, goodWhenUp = true, onClick, tooltip }:
  { label: string; value: string | number; delta?: number | null; goodWhenUp?: boolean; onClick?: () => void; tooltip?: string }) {
  let deltaEl = null;
  if (delta !== undefined && delta !== null && isFinite(delta)) {
    const up = delta > 0;
    const good = delta === 0 ? null : up === goodWhenUp;
    deltaEl = (
      <span className="text-caption" style={{ color: good === null ? "var(--text-secondary)" : good ? "var(--success)" : "var(--danger)" }}>
        {delta === 0 ? "No change" : `${up ? "▲" : "▼"} ${Math.abs(Math.round(delta))}%`} vs previous period
      </span>
    );
  }
  const body = (
    <>
      <span className="text-caption text-fg-muted">{label}</span>
      <span className="text-display font-bold tabular" title={tooltip}>{value}</span>
      {deltaEl ?? <span className="text-caption text-fg-faint">—</span>}
    </>
  );
  const cls = "flex min-h-[104px] flex-col gap-1 rounded-md border border-line bg-surface p-4 text-left";
  return onClick ? <button onClick={onClick} className={clsx(cls, "hover:border-line-hover")}>{body}</button> : <div className={cls}>{body}</div>;
}
