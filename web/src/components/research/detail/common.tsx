"use client";

import Link from "next/link";
import type { ResearchDetail, Source } from "@/lib/types";
import { useWsHref } from "../../providers";
import { Tooltip } from "../../ui/overlay";

export interface DetailProps {
  d: ResearchDetail;
  reload: () => Promise<void>;
  patchRecord: (changes: Record<string, unknown>, summary?: string) => Promise<void>;
  canEdit: boolean;
  ws: string;
}

/** In-page link (e.g. `?tab=hunts`) that keeps the active `?ws=` workspace. */
export function WsLink({ href, ...props }: React.ComponentProps<typeof Link> & { href: string }) {
  const wsHref = useWsHref();
  return <Link href={wsHref(href)} {...props} />;
}

/** Superscript source links; each jumps to its source card. */
export function SourceRefs({ ids, sources }: { ids: string[]; sources: Record<string, Source> }) {
  const wsHref = useWsHref();
  if (!ids?.length) return <sup className="ml-0.5 text-[11px] font-semibold text-danger" title="No supporting source">unsupported</sup>;
  return (
    <sup className="ml-0.5 space-x-0.5 text-[11px]">
      {ids.map((id) => (
        <Tooltip key={id} content={sources[id] ? `${sources[id].publisher} — ${sources[id].title}` : id}>
          <Link href={wsHref(`?tab=sources#source-${id}`)} className="font-mono font-semibold text-accent-text hover:underline">{id.replace("S", "")}</Link>
        </Tooltip>
      ))}
    </sup>
  );
}

export function SectionHeading({ id, children, actions }: { id: string; children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2">
      <h2 id={id} className="scroll-mt-32 text-h2 font-semibold">{children}</h2>
      <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div>
    </div>
  );
}

export function Quote({ children }: { children: React.ReactNode }) {
  return <span className="italic text-fg-strong">“{children}”</span>;
}
