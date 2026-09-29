"use client";

import { Chip } from "./ui/badges";
import { Tooltip } from "./ui/overlay";

/** Table cell chips: max 2 visible, each truncating, "+N" with the full list in a tooltip. */
export function ChipList({ items, mono, max = 2 }: { items: string[]; mono?: boolean; max?: number }) {
  if (!items.length) return <span className="text-fg-faint">—</span>;
  return (
    <span className="flex max-w-[260px] min-w-0 flex-nowrap items-center gap-1">
      {items.slice(0, max).map((i) => <Chip key={i} mono={mono} className="shrink">{i}</Chip>)}
      {items.length > max && <Tooltip content={items.join(", ")}><span className="shrink-0 text-caption text-fg-muted" tabIndex={0}>+{items.length - max}</span></Tooltip>}
    </span>
  );
}
