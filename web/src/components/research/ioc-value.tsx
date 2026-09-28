"use client";

import { Check, ChevronDown, Copy, FileCode2, Fingerprint, Globe, KeyRound, Link2, LockKeyhole, MonitorSmartphone, Network, AtSign, Wallet } from "lucide-react";
import { useState } from "react";
import { IOC_TYPE_LABEL } from "@/lib/constants";
import { defang, isHash, refang, truncateMiddle } from "@/lib/format";
import { copyText } from "@/lib/hooks";
import type { Verdict } from "@/lib/types";
import { VerdictBadge } from "../ui/badges";
import { Menu, Tooltip } from "../ui/overlay";

export const IOC_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  ipv4: Network, ipv6: Network, domain: Globe, url: Link2, sha256: Fingerprint, sha1: Fingerprint, md5: Fingerprint,
  file_name: FileCode2, file_path: FileCode2, email: AtSign, registry: KeyRound, wallet: Wallet, user_agent: MonitorSmartphone,
  mutex: LockKeyhole, other: Fingerprint,
};

function spoken(type: string, v: string) {
  const r = refang(v);
  if (type === "ipv4") return `IP address ${r.split(".").join(" dot ")}`;
  return `${IOC_TYPE_LABEL[type] ?? type} ${r}`;
}

/** The component used for every indicator in the UI (design.md 18.2). Always displayed defanged. */
export function IocValue({ type, value, verdict, sources, compact, onOpen, publishers }:
  { type: string; value: string; verdict?: Verdict; sources?: number; compact?: boolean; onOpen?: () => void; publishers?: string[] }) {
  const [copied, setCopied] = useState<string | null>(null);
  const shown = defang(value, type);
  const display = compact && isHash(type) ? truncateMiddle(shown) : shown;
  const Icon = IOC_ICON[type] ?? Fingerprint;
  const doCopy = async (raw: boolean) => {
    await copyText(raw ? refang(value) : shown);
    setCopied(raw ? "Copied live indicator" : "Copied");
    setTimeout(() => setCopied(null), 1500);
  };
  return (
    <span className="inline-flex max-w-full min-w-0 items-center gap-2" aria-label={`${spoken(type, value)}${verdict ? `, ${verdict}` : ""}`}>
      <Tooltip content={IOC_TYPE_LABEL[type] ?? type}><span className="shrink-0 text-fg-muted"><Icon className="size-4" /></span></Tooltip>
      {onOpen ? (
        <Tooltip content={compact && isHash(type) ? shown : undefined}>
          <button type="button" onClick={onOpen} data-copy={shown} className="min-w-0 truncate text-left font-mono text-mono text-fg hover:underline">{display}</button>
        </Tooltip>
      ) : <span className="min-w-0 truncate font-mono text-mono" title={compact && isHash(type) ? shown : undefined} data-copy={shown}>{display}</span>}
      {verdict && <VerdictBadge verdict={verdict} compact={compact} />}
      {sources !== undefined && sources > 0 && (
        <Tooltip content={publishers?.length ? publishers.join(", ") : `${sources} source${sources === 1 ? "" : "s"}`}>
          <span className="shrink-0 font-mono text-[12px] font-semibold text-fg-muted">×{sources}</span>
        </Tooltip>
      )}
      <span className="inline-flex shrink-0 items-center">
        <Tooltip content={copied ?? "Copy defanged"}>
          <button type="button" onClick={() => doCopy(false)} aria-label="Copy defanged value"
            className="grid size-6 place-items-center rounded-sm text-fg-muted hover:bg-subtle hover:text-fg">
            {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
          </button>
        </Tooltip>
        <Menu width={220} items={[
          { label: "Copy defanged", icon: <Copy />, onSelect: () => doCopy(false) },
          { label: "Copy raw (refanged)", icon: <Copy />, onSelect: () => doCopy(true) },
        ]} trigger={(p) => (
          <button {...p} type="button" aria-label="More copy options" className="grid h-6 w-4 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><ChevronDown className="size-3" /></button>
        )} />
      </span>
    </span>
  );
}
