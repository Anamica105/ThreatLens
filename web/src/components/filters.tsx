"use client";

import clsx from "clsx";
import { ChevronDown } from "lucide-react";
import { Checkbox } from "./ui/forms";
import { Popover } from "./ui/overlay";

/** Filter button that opens a multi-select popover (design.md 15.4). */
export function FilterButton({ label, options, values, onChange, single }:
  { label: string; options: { value: string; label: string; count?: number; dot?: string }[]; values: string[]; onChange: (v: string[]) => void; single?: boolean }) {
  const active = values.length > 0;
  return (
    <Popover width={260} label={`Filter by ${label}`} trigger={(p) => (
      <button {...p} className={clsx("inline-flex h-8 items-center gap-1.5 rounded-sm border px-2.5 text-[13px] font-semibold",
        active ? "border-accent bg-accent-soft text-accent-text" : "border-line-strong bg-surface text-fg hover:bg-subtle")}>
        {label}{active && <span className="tabular">· {values.length}</span>}
        <ChevronDown className="size-4" />
      </button>
    )}>
      {(close) => (
        <div className="max-h-[320px] overflow-y-auto p-2">
          {options.map((o) => (
            <div key={o.value} className="flex h-8 items-center justify-between rounded-sm px-1 hover:bg-subtle">
              <Checkbox checked={values.includes(o.value)}
                onChange={(c) => { if (single) { onChange(c ? [o.value] : []); close(); } else onChange(c ? [...values, o.value] : values.filter((v) => v !== o.value)); }}
                label={<span className="inline-flex items-center gap-2">{o.dot && <span className="size-2 rounded-full" style={{ background: o.dot }} />}{o.label}</span>} />
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

export function ActiveFilters({ chips, onClear }: { chips: { key: string; label: string; onRemove: () => void }[]; onClear: () => void }) {
  if (!chips.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {chips.map((c) => (
        <span key={c.key} className="inline-flex h-7 items-center gap-1 rounded-full bg-chip pr-1 pl-3 text-[13px] text-chip-fg">
          {c.label}
          <button onClick={c.onRemove} aria-label={`Remove filter ${c.label}`} className="grid size-5 place-items-center rounded-full hover:bg-[var(--g-100)] dark:hover:bg-[#2E3440]">×</button>
        </span>
      ))}
      <button onClick={onClear} className="text-[13px] font-semibold text-accent-text hover:underline">Clear all</button>
    </div>
  );
}
