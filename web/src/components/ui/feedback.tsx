"use client";

import clsx from "clsx";
import { CircleAlert, CircleCheck, Info, TriangleAlert, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

/* ------------------------------------------------------------------ Spinner / progress / skeleton */

export function Spinner({ size = 16, className }: { size?: 16 | 20 | 24; className?: string }) {
  return (
    <svg className={clsx("spin shrink-0", className)} width={size} height={size} viewBox="0 0 24 24" aria-hidden>
      <circle cx="12" cy="12" r="10" fill="none" stroke="var(--g-100)" strokeWidth="2.5" />
      <path d="M12 2a10 10 0 0 1 10 10" fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

export function ProgressBar({ value, max, label }: { value?: number; max?: number; label?: string }) {
  const det = value !== undefined && max;
  return (
    <div>
      <div className="relative h-1 overflow-hidden rounded-full bg-[var(--g-100)] dark:bg-[#2E3440]" role="progressbar"
        aria-valuenow={det ? value : undefined} aria-valuemax={det ? max : undefined} aria-label={label}>
        {det ? <div className="h-full rounded-full bg-accent" style={{ width: `${Math.min(100, (100 * (value ?? 0)) / (max || 1))}%` }} />
          : <div className="progress-indeterminate absolute h-full w-2/5 rounded-full bg-accent" />}
      </div>
      {label && <div className="mt-1 text-caption text-fg-muted">{label}</div>}
    </div>
  );
}

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={clsx("skeleton", className)} style={style} aria-hidden />;
}

export function SkeletonRows({ rows = 6, height = 48 }: { rows?: number; height?: number }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 border-b border-line px-4" style={{ height }}>
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-3 flex-1" style={{ maxWidth: `${60 - (i % 3) * 10}%` }} />
          <Skeleton className="h-3 w-16" />
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ Alerts */

type AlertTone = "info" | "success" | "warning" | "danger";
const ALERT_ICON: Record<AlertTone, React.ReactNode> = {
  info: <Info />, success: <CircleCheck />, warning: <TriangleAlert />, danger: <CircleAlert />,
};

export function Alert({ tone = "info", title, children, action, onDismiss, className }:
  { tone?: AlertTone; title?: React.ReactNode; children?: React.ReactNode; action?: React.ReactNode; onDismiss?: () => void; className?: string }) {
  return (
    <div role={tone === "danger" ? "alert" : "status"}
      className={clsx("flex gap-3 rounded-md border px-4 py-3", className)}
      style={{ background: `var(--${tone}-soft)`, borderColor: `var(--${tone}-border)` }}>
      <span className="mt-px shrink-0 [&_svg]:size-5" style={{ color: `var(--${tone})` }}>{ALERT_ICON[tone]}</span>
      <div className="min-w-0 flex-1">
        {title && <div className="text-h4 font-semibold text-fg">{title}</div>}
        {children && <div className="text-fg-strong">{children}</div>}
        {action && <div className="mt-2">{action}</div>}
      </div>
      {onDismiss && <button onClick={onDismiss} aria-label="Dismiss" className="grid size-6 place-items-center rounded-sm text-fg-muted hover:bg-black/5"><X className="size-4" /></button>}
    </div>
  );
}

export function Banner({ tone = "info", children, action }: { tone?: AlertTone; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="flex min-h-11 items-center gap-3 border-b px-6 py-2 text-[14px]"
      style={{ background: `var(--${tone}-soft)`, borderColor: `var(--${tone}-border)` }} role="status">
      <span className="shrink-0 [&_svg]:size-5" style={{ color: `var(--${tone})` }}>{ALERT_ICON[tone]}</span>
      <div className="flex-1 text-fg">{children}</div>
      {action}
    </div>
  );
}

export function EmptyState({ icon, title, body, action }: { icon: React.ReactNode; title: string; body?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="mx-auto flex max-w-[400px] flex-col items-center px-4 py-12 text-center">
      <span className="mb-3 text-fg-faint [&_svg]:size-6">{icon}</span>
      <h3 className="text-h3 font-semibold">{title}</h3>
      {body && <p className="mt-1 text-fg-muted">{body}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="p-6">
      <Alert tone="danger" title="Could not load this page" action={onRetry && <button className="prose-link text-[14px]" onClick={onRetry}>Try again</button>}>
        {error.message}
      </Alert>
    </div>
  );
}

/* ------------------------------------------------------------------ Toasts */

interface Toast { id: number; tone: AlertTone; message: string; action?: { label: string; onClick: () => void } }
const ToastCtx = createContext<(t: Omit<Toast, "id">) => void>(() => undefined);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idRef = useRef(0);
  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = ++idRef.current;
    setToasts((xs) => [{ ...t, id }, ...xs].slice(0, 3));
  }, []);
  const remove = (id: number) => setToasts((xs) => xs.filter((x) => x.id !== id));
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed right-4 bottom-4 z-[1300] flex w-[360px] max-w-[calc(100vw-32px)] flex-col gap-2" aria-live="polite">
        {toasts.map((t) => <ToastItem key={t.id} t={t} onClose={() => remove(t.id)} />)}
      </div>
    </ToastCtx.Provider>
  );
}

function ToastItem({ t, onClose }: { t: Toast; onClose: () => void }) {
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    if (t.tone === "danger" || paused) return;
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [t.tone, paused, onClose]);
  return (
    <div role={t.tone === "danger" ? "alert" : "status"} aria-live={t.tone === "danger" ? "assertive" : "polite"}
      onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} onFocus={() => setPaused(true)} onBlur={() => setPaused(false)}
      className="flex items-start gap-3 rounded-md border border-line bg-raised px-4 py-3 shadow-elev-2">
      <span className="mt-px shrink-0 [&_svg]:size-5" style={{ color: `var(--${t.tone})` }}>{ALERT_ICON[t.tone]}</span>
      <div className="flex-1 text-[14px] text-fg">{t.message}</div>
      {t.action && <button className="text-[14px] font-semibold text-accent-text hover:underline" onClick={() => { t.action!.onClick(); onClose(); }}>{t.action.label}</button>}
      <button onClick={onClose} aria-label="Dismiss" className="grid size-6 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><X className="size-4" /></button>
    </div>
  );
}
