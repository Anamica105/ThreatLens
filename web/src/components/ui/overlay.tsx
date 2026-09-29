"use client";

import clsx from "clsx";
import { ChevronLeft, ChevronRight, X } from "lucide-react";
import { cloneElement, isValidElement, useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

function useMounted() {
  const [m, setM] = useState(false);
  useEffect(() => setM(true), []);
  return m;
}

/* ------------------------------------------------------------------ Tooltip */

export function Tooltip({ content, children, side = "top" }: { content: React.ReactNode; children: React.ReactElement; side?: "top" | "bottom" }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const ref = useRef<HTMLElement | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const id = useId();
  const mounted = useMounted();

  const show = (delay: number) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const el = ref.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      setPos({ x: r.left + r.width / 2, y: side === "top" ? r.top : r.bottom });
      setOpen(true);
    }, delay);
  };
  const hide = () => {
    if (timer.current) clearTimeout(timer.current);
    setOpen(false);
  };
  if (!content || !isValidElement(children)) return children;
  const child = children as React.ReactElement<Record<string, unknown>>;
  const origRef = child.props.ref as React.Ref<HTMLElement> | undefined;
  const trigger = cloneElement(child, {
    ref: (n: HTMLElement) => {
      ref.current = n;
      if (typeof origRef === "function") origRef(n);
      else if (origRef && typeof origRef === "object") (origRef as React.MutableRefObject<HTMLElement | null>).current = n;
    },
    onMouseEnter: (e: React.MouseEvent) => { show(400); (child.props.onMouseEnter as ((e: React.MouseEvent) => void) | undefined)?.(e); },
    onMouseLeave: (e: React.MouseEvent) => { hide(); (child.props.onMouseLeave as ((e: React.MouseEvent) => void) | undefined)?.(e); },
    onFocus: (e: React.FocusEvent) => { show(0); (child.props.onFocus as ((e: React.FocusEvent) => void) | undefined)?.(e); },
    onBlur: (e: React.FocusEvent) => { hide(); (child.props.onBlur as ((e: React.FocusEvent) => void) | undefined)?.(e); },
    "aria-describedby": open ? id : undefined,
  });
  return (
    <>
      {trigger}
      {mounted && open && pos && createPortal(
        <div id={id} role="tooltip"
          className="pointer-events-none fixed z-[1400] max-w-[280px] rounded-sm bg-[var(--g-900)] px-2 py-1.5 text-[12px] leading-4 font-medium text-white dark:bg-[var(--g-700)]"
          style={{ left: pos.x, top: side === "top" ? pos.y - 6 : pos.y + 6, transform: side === "top" ? "translate(-50%, -100%)" : "translate(-50%, 0)" }}>
          {content}
        </div>,
        document.body,
      )}
    </>
  );
}

/* ------------------------------------------------------------------ Popover */

export function Popover({ trigger, children, open, onOpenChange, align = "start", width, className, label }:
  { trigger: (p: { ref: React.Ref<HTMLButtonElement>; onClick: () => void; "aria-expanded": boolean; "aria-haspopup": "dialog" | "menu" }) => React.ReactNode;
    children: React.ReactNode | ((close: () => void) => React.ReactNode); open?: boolean; onOpenChange?: (o: boolean) => void; align?: "start" | "end"; width?: number; className?: string; label?: string }) {
  const [inner, setInner] = useState(false);
  const isOpen = open ?? inner;
  const setOpen = useCallback((o: boolean) => { setInner(o); onOpenChange?.(o); }, [onOpenChange]);
  const btn = useRef<HTMLButtonElement | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const mounted = useMounted();

  useLayoutEffect(() => {
    if (!isOpen || !btn.current) return;
    const place = () => {
      const r = btn.current!.getBoundingClientRect();
      const w = width ?? panel.current?.offsetWidth ?? 240;
      let left = align === "end" ? r.right - w : r.left;
      left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
      let top = r.bottom + 6;
      const h = panel.current?.offsetHeight ?? 0;
      if (top + h > window.innerHeight - 8 && r.top - h - 6 > 8) top = r.top - h - 6;
      setPos({ top, left });
    };
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => { window.removeEventListener("resize", place); window.removeEventListener("scroll", place, true); };
  }, [isOpen, align, width]);

  useEffect(() => {
    if (!isOpen) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (panel.current?.contains(t) || btn.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setOpen(false); btn.current?.focus(); }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [isOpen, setOpen]);

  const close = () => setOpen(false);
  return (
    <>
      {trigger({ ref: btn, onClick: () => setOpen(!isOpen), "aria-expanded": isOpen, "aria-haspopup": "dialog" })}
      {mounted && isOpen && createPortal(
        <div ref={panel} role="dialog" aria-label={label}
          className={clsx("fixed z-[1000] rounded-md border border-line bg-raised shadow-elev-2", className)}
          style={{ top: pos?.top ?? -9999, left: pos?.left ?? -9999, width }}>
          {typeof children === "function" ? children(close) : children}
        </div>,
        document.body,
      )}
    </>
  );
}

/* ------------------------------------------------------------------ Menu */

export interface MenuItem { label: string; icon?: React.ReactNode; onSelect: () => void; danger?: boolean; disabled?: boolean; shortcut?: string; divider?: boolean }

export function Menu({ trigger, items, align = "end", width = 200, onOpenChange }:
  { trigger: (p: { ref: React.Ref<HTMLButtonElement>; onClick: () => void; "aria-expanded": boolean; "aria-haspopup": "dialog" | "menu" }) => React.ReactNode; items: MenuItem[]; align?: "start" | "end"; width?: number; onOpenChange?: (o: boolean) => void }) {
  const [open, setOpenState] = useState(false);
  const setOpen = useCallback((o: boolean) => { setOpenState(o); onOpenChange?.(o); }, [onOpenChange]);
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement | null>(null);
  const enabled = items.filter((i) => !i.divider);
  useEffect(() => {
    if (open) {
      setActive(0);
      setTimeout(() => (listRef.current?.querySelector("[role=menuitem]") as HTMLElement | null)?.focus(), 0);
    }
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    const els = Array.from(listRef.current?.querySelectorAll<HTMLElement>("[role=menuitem]:not([aria-disabled=true])") ?? []);
    const i = els.indexOf(document.activeElement as HTMLElement);
    if (e.key === "ArrowDown") { e.preventDefault(); els[(i + 1) % els.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); els[(i - 1 + els.length) % els.length]?.focus(); }
    else if (e.key === "Home") { e.preventDefault(); els[0]?.focus(); }
    else if (e.key === "End") { e.preventDefault(); els[els.length - 1]?.focus(); }
    else if (e.key.length === 1) {
      const hit = els.find((el) => el.textContent?.toLowerCase().startsWith(e.key.toLowerCase()));
      hit?.focus();
    }
  };
  void active; void enabled;
  return (
    <Popover open={open} onOpenChange={setOpen} align={align} width={width} trigger={(p) => trigger({ ...p, "aria-haspopup": "menu" })}>
      {(close) => (
        <div ref={listRef} role="menu" className="p-1" onKeyDown={onKey}>
          {items.map((it, i) =>
            it.divider ? <div key={i} className="my-1 h-px bg-[var(--border-subtle)]" role="separator" /> : (
              <button key={i} role="menuitem" type="button" aria-disabled={it.disabled || undefined} disabled={it.disabled}
                onClick={() => { close(); it.onSelect(); }}
                className={clsx("flex h-8 w-full items-center gap-2 rounded-sm px-2 text-left text-[14px] [&_svg]:size-4 disabled:opacity-50",
                  it.danger ? "text-danger hover:bg-danger-soft focus-visible:bg-danger-soft" : "text-fg hover:bg-subtle focus-visible:bg-subtle",
                  "focus-visible:outline-none")}>
                {it.icon && <span className={it.danger ? "" : "text-fg-muted"}>{it.icon}</span>}
                <span className="flex-1 truncate">{it.label}</span>
                {it.shortcut && <span className="font-mono text-[12px] text-fg-faint">{it.shortcut}</span>}
              </button>
            ),
          )}
        </div>
      )}
    </Popover>
  );
}

/* ------------------------------------------------------------------ Dialog */

const DIALOG_W = { sm: 400, md: 560, lg: 800 };

function useFocusTrap(active: boolean, container: React.RefObject<HTMLElement | null>, onEscape?: () => void) {
  useEffect(() => {
    if (!active) return;
    const prev = document.activeElement as HTMLElement | null;
    const el = container.current;
    const focusables = () => Array.from(el?.querySelectorAll<HTMLElement>("a[href],button:not([disabled]),input:not([disabled]),select,textarea,[tabindex]:not([tabindex='-1'])") ?? []);
    setTimeout(() => {
      const auto = el?.querySelector<HTMLElement>("[data-autofocus]");
      (auto ?? focusables()[0] ?? el)?.focus();
    }, 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && onEscape) { e.stopPropagation(); onEscape(); }
      if (e.key !== "Tab") return;
      const f = focusables();
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [active, container, onEscape]);
}

export function Dialog({ open, onClose, title, children, footer, size = "md", description }:
  { open: boolean; onClose: () => void; title: string; children?: React.ReactNode; footer?: React.ReactNode; size?: "sm" | "md" | "lg"; description?: string }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const mounted = useMounted();
  useFocusTrap(open, ref, onClose);
  if (!mounted || !open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[1200] grid place-items-center p-4" style={{ background: "var(--scrim)" }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}
        className="flex max-h-[calc(100vh-32px)] w-full flex-col rounded-lg border border-line bg-raised shadow-elev-3"
        style={{ maxWidth: DIALOG_W[size] }}>
        <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-2">
          <div>
            <h2 className="text-h2 font-semibold">{title}</h2>
            {description && <p className="mt-1 text-fg-muted">{description}</p>}
          </div>
          <button onClick={onClose} aria-label="Close" className="grid size-8 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><X className="size-5" /></button>
        </div>
        <div className="overflow-y-auto px-6 pt-2 pb-6">{children}</div>
        {footer && <div className="flex justify-end gap-4 border-t border-line px-6 py-4">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

/* ------------------------------------------------------------------ Drawer */

export function Drawer({ open, onClose, title, children, width = 480, onPrev, onNext, subtitle, actions }:
  { open: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode; width?: number; onPrev?: () => void; onNext?: () => void; subtitle?: React.ReactNode; actions?: React.ReactNode }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const mounted = useMounted();
  const [w, setW] = useState(width);
  const [wide, setWide] = useState(true);
  useEffect(() => setW(width), [width]);
  useEffect(() => {
    const m = () => setWide(window.innerWidth >= 1280);
    m();
    window.addEventListener("resize", m);
    return () => window.removeEventListener("resize", m);
  }, []);
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, [open, onClose]);
  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault();
    const x0 = e.clientX, w0 = w;
    const move = (ev: MouseEvent) => setW(Math.max(400, Math.min(window.innerWidth - 80, w0 + (x0 - ev.clientX))));
    const up = () => { document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  };
  if (!mounted || !open) return null;
  return createPortal(
    <>
      {!wide && <div className="fixed inset-0 z-[1100]" style={{ background: "var(--scrim)" }} onClick={onClose} />}
      <aside ref={ref} role="dialog" aria-label={typeof title === "string" ? title : "Details"}
        className="fixed top-0 right-0 bottom-0 z-[1100] flex max-w-full flex-col rounded-l-lg border-l border-line bg-raised shadow-elev-3"
        style={{ width: w }}>
        <div className="absolute top-0 bottom-0 left-0 w-1.5 cursor-col-resize" onMouseDown={startDrag} aria-hidden />
        <div className="flex items-start gap-2 border-b border-line px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="text-h3 font-semibold break-words">{title}</div>
            {subtitle && <div className="mt-0.5 text-body-sm text-fg-muted">{subtitle}</div>}
          </div>
          {actions}
          {onPrev && <button onClick={onPrev} aria-label="Previous" className="grid size-8 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><ChevronLeft className="size-5" /></button>}
          {onNext && <button onClick={onNext} aria-label="Next" className="grid size-8 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><ChevronRight className="size-5" /></button>}
          <button onClick={onClose} aria-label="Close" className="grid size-8 place-items-center rounded-sm text-fg-muted hover:bg-subtle"><X className="size-5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </aside>
    </>,
    document.body,
  );
}
