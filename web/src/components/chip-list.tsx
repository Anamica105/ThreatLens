"use client";

import { Chip } from "./ui/badges";
import { Tooltip } from "./ui/overlay";

/** Table cell chips: max 2 visible, "+N" with the full list in a tooltip. */
export function ChipList({ items, mono, max = 2 }: { items: string[]; mono?: boolean; max?: number }) {
  if (!items.length) return <span className="text-fg-faint">—</span>;
  return (
    <span className="flex max-w-[260px] flex-nowrap items-center gap-1">
      {items.slice(0, max).map((i) => <Chip key={i} mono={mono}>{i}</Chip>)}
      {items.length > max && <Tooltip content={items.join(", ")}><span className="text-caption text-fg-muted">+{items.length - max}</span></Tooltip>}
    </span>
  );
}
