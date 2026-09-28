"use client";

import clsx from "clsx";
import { ChevronLeft, ChevronRight } from "lucide-react";
import Link from "next/link";
import { useRef } from "react";
import { useWsHref } from "../providers";
import { CountBadge } from "./badges";
import { Select } from "./forms";
import { Menu } from "./overlay";

export interface Crumb { label: string; href?: string; mono?: boolean }

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  const wsHref = useWsHref();
  const collapsed = items.length > 4;
  const shown = collapsed ? [items[0], { label: "…" } as Crumb, ...items.slice(-2)] : items;
  const hidden = collapsed ? items.slice(1, -2) : [];
  const parent = items[items.length - 2];
  return (
    <nav aria-label="Breadcrumb" className="text-body-sm">
      {parent && (
        <Link href={wsHref(parent.href ?? "#")} className="inline-flex items-center gap-1 text-fg-muted hover:text-fg sm:hidden">
          <ChevronLeft className="size-4" />{parent.label}
        </Link>
      )}
      <ol className="hidden flex-wrap items-center sm:flex">
        {shown.map((c, i) => {
          const last = i === shown.length - 1;
          return (
            <li key={i} className="flex items-center">
              {c.label === "…" && hidden.length ? (
                <Menu align="start" items={hidden.map((h) => ({ label: h.label, onSelect: () => { if (h.href) window.location.href = wsHref(h.href); } }))}
                  trigger={(p) => <button {...p} className="rounded-sm px-1 text-fg-muted hover:text-fg" aria-label="Show hidden levels">…</button>} />
              ) : last ? (
                <span aria-current="page" className={clsx("max-w-[32ch] truncate font-medium text-fg", c.mono && "font-mono text-mono-sm")} title={c.label}>{c.label}</span>
              ) : (
                <Link href={wsHref(c.href ?? "#")} className={clsx("max-w-[32ch] truncate text-fg-muted hover:text-fg hover:underline", c.mono && "font-mono text-mono-sm")} title={c.label}>{c.label}</Link>
              )}
              {!last && <span aria-hidden className="mx-2 text-[var(--g-300)]">/</span>}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export function PageHeader({ crumbs, title, description, actions, children }:
  { crumbs?: Crumb[]; title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <header className="pt-6 pb-6">
      {crumbs && <div className="mb-2"><Breadcrumbs items={crumbs} /></div>}
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h1 className="text-h1 font-[650]">{title}</h1>
          {description && <p className="mt-1 text-fg-muted">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

export function Page({ children, className, wide }: { children: React.ReactNode; className?: string; wide?: boolean }) {
  return <div className={clsx("mx-auto w-full px-4 pb-16 md:px-6", wide ? "max-w-[1440px]" : "max-w-[1440px]", className)}>{children}</div>;
}

export function Panel({ title, actions, children, className, bodyClassName, id }:
  { title?: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode; className?: string; bodyClassName?: string; id?: string }) {
  return (
    <section id={id} className={clsx("min-w-0 rounded-md border border-line bg-surface", className)}>
      {(title || actions) && (
        <div className="flex items-center justify-between gap-2 px-4 pt-4">
          {title && <h2 className="text-h4 font-semibold">{title}</h2>}
          {actions && <div className="flex items-center gap-1">{actions}</div>}
        </div>
      )}
      <div className={clsx("p-4", (title || actions) && "pt-3", bodyClassName)}>{children}</div>
    </section>
  );
}

export interface TabDef { id: string; label: string; count?: number }

/** Page-level underline tabs; roving tabindex, arrow keys. */
export function Tabs({ tabs, value, onChange, ariaLabel }: { tabs: TabDef[]; value: string; onChange: (id: string) => void; ariaLabel: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const idx = tabs.findIndex((t) => t.id === value);
  const onKey = (e: React.KeyboardEvent) => {
    let n = idx;
    if (e.key === "ArrowRight") n = (idx + 1) % tabs.length;
    else if (e.key === "ArrowLeft") n = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") n = 0;
    else if (e.key === "End") n = tabs.length - 1;
    else return;
    e.preventDefault();
    refs.current[n]?.focus();
  };
  return (
    <div className="fade-x -mx-1 overflow-x-auto px-1">
      <div role="tablist" aria-label={ariaLabel} className="flex min-w-max gap-6 border-b border-line" onKeyDown={onKey}>
        {tabs.map((t, i) => {
          const sel = t.id === value;
          return (
            <button key={t.id} ref={(el) => { refs.current[i] = el; }} role="tab" id={`tab-${t.id}`} aria-selected={sel} aria-controls={`panel-${t.id}`}
              tabIndex={sel ? 0 : -1} onClick={() => onChange(t.id)}
              className={clsx("relative -mb-px flex h-10 items-center gap-1.5 text-[14px] font-semibold transition-colors",
                sel ? "text-fg" : "text-fg-muted hover:text-fg")}>
              {t.label}
              {t.count !== undefined && <CountBadge>{t.count}</CountBadge>}
              <span className={clsx("absolute right-0 bottom-0 left-0 h-0.5 rounded-full transition-colors duration-[var(--motion-base)]", sel ? "bg-accent" : "bg-transparent")} />
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** Pill-style secondary tabs (platform switcher inside query blocks). */
export function PillTabs({ tabs, value, onChange, ariaLabel }: { tabs: { id: string; label: string }[]; value: string; onChange: (id: string) => void; ariaLabel: string }) {
  return (
    <div role="tablist" aria-label={ariaLabel} className="flex flex-wrap gap-1">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={t.id === value} onClick={() => onChange(t.id)}
          className={clsx("h-7 rounded-sm px-2.5 text-[13px] font-semibold transition-colors",
            t.id === value ? "bg-accent-soft text-accent-text" : "text-fg-muted hover:bg-subtle hover:text-fg")}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function DefinitionList({ items }: { items: { label: string; value: React.ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-2">
      {items.map((it) => (
        <div key={it.label} className="contents">
          <dt className="pt-0.5 text-caption text-fg-muted">{it.label}</dt>
          <dd className="min-w-0 break-words text-[14px]">{it.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Pagination({ page, pageSize, total, onPage, onPageSize }:
  { page: number; pageSize: number; total: number; onPage: (p: number) => void; onPageSize?: (n: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total ? (page - 1) * pageSize + 1 : 0;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-body-sm text-fg-muted">
      <span className="tabular">{from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}</span>
      <div className="flex items-center gap-3">
        {onPageSize && (
          <label className="flex items-center gap-2">Rows
            <Select size="sm" value={String(pageSize)} onChange={(v) => onPageSize(Number(v))} options={[25, 50, 100].map((n) => ({ value: String(n), label: String(n) }))} ariaLabel="Rows per page" />
          </label>
        )}
        <button aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)} className="grid size-7 place-items-center rounded-sm hover:bg-subtle disabled:opacity-40"><ChevronLeft className="size-4" /></button>
        <span className="flex items-center gap-1">
          <input aria-label="Page number" defaultValue={page} key={page} onKeyDown={(e) => { if (e.key === "Enter") { const n = Number((e.target as HTMLInputElement).value); if (n >= 1 && n <= pages) onPage(n); } }}
            className="h-7 w-10 rounded-sm border border-line-strong bg-surface text-center tabular text-fg" /> / {pages}
        </span>
        <button aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)} className="grid size-7 place-items-center rounded-sm hover:bg-subtle disabled:opacity-40"><ChevronRight className="size-4" /></button>
      </div>
    </div>
  );
}

/** Real <table> markup with sticky header; container scrolls horizontally, never the page. */
export function Table({ children, className, compact }: { children: React.ReactNode; className?: string; compact?: boolean }) {
  return (
    <div className={clsx("overflow-x-auto", className)}>
      <table className={clsx("tl-table w-full border-collapse", compact ? "tl-compact" : "tl-comfortable")}>{children}</table>
    </div>
  );
}
