"use client";

import clsx from "clsx";
import { ChevronDown, X } from "lucide-react";
import { Checkbox } from "./ui/forms";
import { Popover } from "./ui/overlay";

export interface FilterOption { value: string; label: string; count?: number; dot?: string }

/** Compact filter trigger (28 px) shared by every filter popover so all filter bars look the same. */
export function FilterTrigger({ label, count, active, ...p }:
  { label: string; count?: number; active: boolean } & React.ButtonHTMLAttributes<HTMLButtonElement> & { ref?: React.Ref<HTMLButtonElement> }) {
  return (
    <button type="button" {...p}
      className={clsx("inline-flex h-8 max-w-full shrink-0 items-center gap-1.5 rounded-sm border px-2.5 text-[13px] font-semibold whitespace-nowrap transition-colors duration-[var(--motion-instant)]",
        active ? "border-accent bg-accent-soft text-accent-text" : "border-line-strong bg-surface text-fg hover:border-line-hover hover:bg-subtle")}>
      <span className="truncate">{label}</span>
      {active && count !== undefined && <span className="tabular">· {count}</span>}
      <ChevronDown className="size-4 shrink-0 opacity-70" />
    </button>
  );
}

/** Filter button that opens a multi-select popover (design.md 15.4). */
export function FilterButton({ label, options, values, onChange, single }:
  { label: string; options: FilterOption[]; values: string[]; onChange: (v: string[]) => void; single?: boolean }) {
  const active = values.length > 0;
  const selectedLabel = single && active ? options.find((o) => o.value === values[0])?.label ?? values[0] : null;
  return (
    <Popover width={260} label={`Filter by ${label}`} trigger={(p) => (
      <FilterTrigger {...p} label={selectedLabel ? `${label}: ${selectedLabel}` : label} count={single ? undefined : values.length} active={active} />
    )}>
      {(close) => (
        <div className="max-h-[320px] overflow-y-auto p-2">
          {options.map((o) => (
            <div key={o.value} className="flex h-8 items-center justify-between gap-2 rounded-sm px-1 hover:bg-subtle">
              <Checkbox checked={values.includes(o.value)}
                onChange={(c) => { if (single) { onChange(c ? [o.value] : []); close(); } else onChange(c ? [...values, o.value] : values.filter((v) => v !== o.value)); }}
                label={<span className="inline-flex min-w-0 items-center gap-2">{o.dot && <span className="size-2 shrink-0 rounded-full" style={{ background: o.dot }} />}<span className="truncate">{o.label}</span></span>} />
              {o.count !== undefined && <span className="text-caption tabular text-fg-muted">{o.count}</span>}
            </div>
          ))}
          {!options.length && <p className="px-2 py-1 text-fg-muted">No options</p>}
          {active && <button onClick={() => { onChange([]); close(); }} className="mt-1 w-full rounded-sm px-2 py-1.5 text-left text-[13px] font-semibold text-accent-text hover:bg-accent-soft">Clear</button>}
        </div>
      )}
    </Popover>
  );
}

export interface ActiveChip { key: string; label: string; onRemove: () => void }

/** Removable active-filter chips (design.md 17: filter chip, 28 px, fully rounded) with "Clear all". */
export function ActiveFilters({ chips, onClear, className }: { chips: ActiveChip[]; onClear: () => void; className?: string }) {
  if (!chips.length) return null;
  return (
    <div className={clsx("flex min-w-0 flex-wrap items-center gap-2", className)}>
      {chips.map((c) => (
        <span key={c.key} title={c.label} className="inline-flex h-7 max-w-full min-w-0 items-center gap-1 rounded-full bg-chip pr-1 pl-3 text-[13px] text-chip-fg">
          <span className="min-w-0 truncate">{c.label}</span>
          <button onClick={c.onRemove} aria-label={`Remove filter ${c.label}`}
            className="grid size-5 shrink-0 place-items-center rounded-full text-fg-muted hover:bg-[var(--g-100)] hover:text-fg dark:hover:bg-[#2E3440]"><X className="size-3.5" /></button>
        </span>
      ))}
      <button onClick={onClear} className="h-7 shrink-0 rounded-sm px-1.5 text-[13px] font-semibold text-accent-text hover:bg-accent-soft">Clear all</button>
    </div>
  );
}
