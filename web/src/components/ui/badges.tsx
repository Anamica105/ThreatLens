"use client";

import clsx from "clsx";
import Link from "next/link";
import {
  Activity, BadgeCheck, BookOpenText, Bug, CircleCheck, CircleHelp, CircleMinus, Clock, Code, Flag, OctagonAlert, Route,
  ScanSearch, ShieldCheck, TriangleAlert, UserRoundSearch,
} from "lucide-react";
import { CLASSIFICATION, CREDIBILITY, QUERY_STATUS, RELIABILITY, RESEARCH_STATUS, RESULT_STATUS, SEVERITY, TLP_SQUARE, VERDICT, type Tone } from "@/lib/constants";
import type { ResearchStatus, ResultStatus, Severity, Verdict } from "@/lib/types";
import { Tooltip } from "./overlay";

const TONE: Record<Tone, { bg: string; fg: string; dot: string }> = {
  neutral: { bg: "var(--neutral-chip-bg)", fg: "var(--neutral-chip-text)", dot: "var(--g-400)" },
  muted: { bg: "var(--neutral-chip-bg)", fg: "var(--text-secondary)", dot: "var(--g-300)" },
  accent: { bg: "var(--accent-soft)", fg: "var(--accent-text)", dot: "var(--accent)" },
  info: { bg: "var(--info-soft)", fg: "var(--info)", dot: "var(--info)" },
  success: { bg: "var(--success-soft)", fg: "var(--success)", dot: "var(--success)" },
  warning: { bg: "var(--warning-soft)", fg: "var(--warning)", dot: "var(--warning)" },
  danger: { bg: "var(--danger-soft)", fg: "var(--danger)", dot: "var(--danger)" },
  critical: { bg: "var(--sev-critical-soft)", fg: "var(--sev-critical-text)", dot: "var(--sev-critical)" },
};

/** Status pill: fully rounded, only for states that change over time. */
export function Pill({ tone, children, dot = true, running, outline, icon, className, title }:
  { tone: Tone; children: React.ReactNode; dot?: boolean; running?: boolean; outline?: boolean; icon?: React.ReactNode; className?: string; title?: string }) {
  const t = TONE[tone];
  return (
    <span
      title={title}
      className={clsx("inline-flex h-[22px] items-center gap-1.5 rounded-full px-2 text-[12px] font-semibold leading-none whitespace-nowrap", className)}
      style={{ background: outline ? "transparent" : t.bg, color: t.fg, boxShadow: outline ? `inset 0 0 0 1px ${t.dot}` : undefined }}
    >
      {icon ? <span className="[&_svg]:size-3.5">{icon}</span> : dot && <span className={clsx("size-1.5 rounded-full", running && "dot-running")} style={{ background: t.dot }} />}
      {children}
    </span>
  );
}

export function StatusPill({ status }: { status: ResearchStatus }) {
  const s = RESEARCH_STATUS[status] ?? { label: status, tone: "neutral" as Tone };
  return <Pill tone={s.tone} running={status === "running"}>{s.label}</Pill>;
}

const RESULT_ICON: Record<ResultStatus, React.ReactNode> = {
  confirmed: <OctagonAlert />, suspicious: <TriangleAlert />, no_evidence: <CircleCheck />, not_applicable: <CircleMinus />, pending: <Clock />,
};

export function ResultPill({ status, suffix }: { status: ResultStatus; suffix?: string }) {
  const s = RESULT_STATUS[status] ?? RESULT_STATUS.pending;
  return <Pill tone={s.tone} outline={status === "pending"} icon={RESULT_ICON[status]}>{s.label}{suffix ? ` · ${suffix}` : ""}</Pill>;
}

export function QueryStatusPill({ status }: { status: string }) {
  const s = QUERY_STATUS[status] ?? { label: status, tone: "neutral" as Tone };
  return <Pill tone={s.tone} icon={status === "deployed" ? <BadgeCheck /> : undefined}>{s.label}</Pill>;
}

/** 4px-radius badge for attributes. */
export function Badge({ tone = "neutral", children, square, className, title, mono }:
  { tone?: Tone; children: React.ReactNode; square?: string; className?: string; title?: string; mono?: boolean }) {
  const t = TONE[tone];
  return (
    <span title={title} className={clsx("inline-flex h-[22px] items-center gap-1.5 rounded-sm px-2 text-[12px] font-semibold leading-none whitespace-nowrap", mono && "font-mono", className)}
      style={{ background: t.bg, color: t.fg }}>
      {square && <span className="size-2 rounded-[1px]" style={{ background: square }} />}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = SEVERITY[severity] ?? SEVERITY.medium;
  return (
    <span className={clsx("inline-flex h-[22px] items-center gap-1.5 rounded-sm px-2 text-[12px] font-semibold leading-none", className)}
      style={{ background: s.soft, color: s.text }}>
      <span className="size-2 rounded-[1px]" style={{ background: s.solid }} />
      {s.label}
    </span>
  );
}

export function TlpBadge({ tlp }: { tlp: string }) {
  return (
    <span className="inline-flex h-[22px] items-center gap-1.5 rounded-sm px-2 text-[12px] font-semibold leading-none"
      style={{ background: "var(--tlp-badge-bg)", color: "var(--tlp-badge-text)" }}>
      <span className="size-2 rounded-[1px]" style={{ background: TLP_SQUARE[tlp] ?? "var(--tlp-amber)", border: tlp === "CLEAR" ? "1px solid var(--tlp-clear-border)" : undefined }} />
      TLP:{tlp}
    </span>
  );
}

const VERDICT_ICON: Record<Verdict, React.ReactNode> = {
  malicious: <OctagonAlert />, suspicious: <TriangleAlert />, benign: <ShieldCheck />, unknown: <CircleHelp />, expired: <Clock />,
};

export function VerdictBadge({ verdict, compact }: { verdict: Verdict; compact?: boolean }) {
  const v = VERDICT[verdict] ?? VERDICT.unknown;
  const t = TONE[v.tone];
  if (compact)
    return (
      <Tooltip content={v.label}>
        <span className="inline-flex items-center" aria-label={v.label}><span className="size-2 rounded-full" style={{ background: t.dot }} /></span>
      </Tooltip>
    );
  return (
    <span className="inline-flex h-5 items-center gap-1 rounded-sm px-1.5 text-[12px] font-semibold leading-none [&_svg]:size-3.5" style={{ background: t.bg, color: t.fg }}>
      {VERDICT_ICON[verdict]}
      {v.label}
    </span>
  );
}

export function CountBadge({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={clsx("inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[11px] font-semibold tabular leading-none", className)}
      style={{ background: "var(--count-bg)", color: "var(--count-text)" }}>
      {children}
    </span>
  );
}

const CLS_ICON: Record<string, React.ReactNode> = {
  bug: <Bug />, flag: <Flag />, "user-round-search": <UserRoundSearch />, "book-open-text": <BookOpenText />, route: <Route />,
  activity: <Activity />, "scan-search": <ScanSearch />, code: <Code />,
};

export function ClassIcon({ kind, className }: { kind: string; className?: string }) {
  const c = CLASSIFICATION[kind];
  if (!c) return null;
  return <span className={clsx("inline-flex [&_svg]:size-4", className)} style={{ color: c.color }}>{CLS_ICON[c.icon]}</span>;
}

/** Entity chip: actor, malware, CVE, industry. Leading classification dot; links to its library page. */
export function Chip({ children, href, dot, icon, className, title, onRemove, mono }:
  { children: React.ReactNode; href?: string; dot?: string; icon?: React.ReactNode; className?: string; title?: string; onRemove?: () => void; mono?: boolean }) {
  const inner = (
    <>
      {dot && <span className="size-2 rounded-full shrink-0" style={{ background: dot }} />}
      {icon && <span className="[&_svg]:size-3.5 text-fg-muted">{icon}</span>}
      <span className={clsx("truncate", mono && "font-mono text-[12px]")}>{children}</span>
      {onRemove && (
        <button type="button" onClick={onRemove} aria-label={`Remove ${typeof children === "string" ? children : ""}`}
          className="-mr-1 ml-0.5 grid size-4 place-items-center rounded-sm text-fg-muted hover:bg-[var(--g-100)] hover:text-fg dark:hover:bg-[#2E3440]">×</button>
      )}
    </>
  );
  const cls = clsx("inline-flex h-6 max-w-[260px] items-center gap-1.5 rounded-sm bg-chip px-2 text-[13px] font-medium text-chip-fg", href && "hover:bg-[var(--g-100)] dark:hover:bg-[#2E3440]", className);
  if (href) return <Link href={href} className={cls} title={title}>{inner}</Link>;
  return <span className={cls} title={title}>{inner}</span>;
}

export function AttackChip({ id, name, tactic, href }: { id: string; name?: string; tactic?: string; href?: string }) {
  const body = (
    <span className="inline-flex h-6 items-center gap-1.5 rounded-sm bg-chip px-2 text-[13px] text-chip-fg">
      <span className="font-mono text-[12px] font-semibold text-accent-text">{id}</span>
      {name && <span className="max-w-[220px] truncate">{name}</span>}
    </span>
  );
  const tip = (
    <span>
      {tactic ? `${tactic} · ` : ""}{name ?? id}
      <br />
      <span className="opacity-75">attack.mitre.org/techniques/{id.replace(".", "/")}</span>
    </span>
  );
  return (
    <Tooltip content={tip}>
      {href ? <Link href={href}>{body}</Link> : <a href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer">{body}</a>}
    </Tooltip>
  );
}

export function PlatformChip({ name, status }: { name: string; status?: string }) {
  const tone = status ? (QUERY_STATUS[status]?.tone ?? "neutral") : null;
  return (
    <span className="inline-flex h-6 items-center gap-1.5 rounded-sm bg-chip px-2 text-[12px] font-semibold text-chip-fg">
      {tone && <span className="size-1.5 rounded-full" style={{ background: TONE[tone].dot }} />}
      {name}
    </span>
  );
}

export function ConfidenceBadge({ level }: { level: string }) {
  const n = level === "high" ? 3 : level === "moderate" ? 2 : 1;
  return (
    <span className="inline-flex h-[22px] items-center gap-1.5 rounded-sm bg-chip px-2 text-[12px] font-semibold text-chip-fg">
      <span className="flex items-end gap-[2px]" aria-hidden>
        {[1, 2, 3].map((i) => (
          <span key={i} className="w-[3px] rounded-[1px]" style={{ height: 4 + i * 2, background: i <= n ? "var(--text-strong)" : "var(--g-300)" }} />
        ))}
      </span>
      {level.charAt(0).toUpperCase() + level.slice(1)} confidence
    </span>
  );
}

export function SourceRating({ reliability, credibility }: { reliability: string; credibility: number }) {
  return (
    <Tooltip content={`${RELIABILITY[reliability] ?? "Unknown"} · ${CREDIBILITY[credibility] ?? "Unknown"}`}>
      <span className="inline-flex h-[22px] items-center rounded-sm bg-chip px-2 font-mono text-[12px] font-bold text-chip-fg">
        {reliability}{credibility}
      </span>
    </Tooltip>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded-xs border border-line-strong border-b-[var(--g-300)] bg-[var(--bg-code)] px-1.5 font-mono text-[12px] text-fg-muted">
      {children}
    </kbd>
  );
}

export function Avatar({ initials, size = 24, title }: { initials?: string; size?: number; title?: string }) {
  return (
    <span title={title} className="inline-grid shrink-0 place-items-center rounded-full bg-accent-soft font-semibold text-accent-text"
      style={{ width: size, height: size, fontSize: size <= 20 ? 9 : 11 }}>
      {initials ?? "?"}
    </span>
  );
}

export function GeneratedBadge({ state }: { state?: string }) {
  if (!state || state === "approved") return null;
  if (state === "edited") return <Badge tone="neutral">Edited</Badge>;
  return <Badge tone="info">Generated — review before publishing</Badge>;
}
