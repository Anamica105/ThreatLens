"use client";

import clsx from "clsx";
import { Check, ChevronDown, CircleAlert, Search } from "lucide-react";
import { forwardRef, useId, useRef, useState } from "react";
import { Chip } from "./badges";
import { Popover } from "./overlay";

export function Field({ label, optional, help, error, children, htmlFor, className }:
  { label?: React.ReactNode; optional?: boolean; help?: React.ReactNode; error?: string; children: React.ReactNode; htmlFor?: string; className?: string }) {
  return (
    <div className={className}>
      {label && (
        <div className="mb-1.5 flex items-baseline justify-between gap-2">
          <label htmlFor={htmlFor} className="text-[13px] leading-[18px] font-semibold text-fg">{label}</label>
          {optional && <span className="text-caption text-fg-muted">Optional</span>}
        </div>
      )}
      {children}
      {error ? (
        <p id={htmlFor ? `${htmlFor}-error` : undefined} className="mt-1 flex items-center gap-1 text-caption text-danger"><CircleAlert className="size-3.5" />{error}</p>
      ) : help ? <p className="mt-1 text-caption text-fg-muted">{help}</p> : null}
    </div>
  );
}

const inputCls =
  "w-full rounded-sm border bg-surface text-fg placeholder:text-fg-faint transition-colors duration-[var(--motion-instant)] " +
  "hover:border-line-hover focus:border-accent focus:outline-none focus:ring-2 focus:ring-[color-mix(in_srgb,var(--accent)_30%,transparent)] " +
  "disabled:cursor-not-allowed disabled:border-line disabled:bg-[var(--disabled-bg)] disabled:text-[var(--disabled-text)]";

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean; prefixIcon?: React.ReactNode; suffix?: React.ReactNode; inputSize?: "sm" | "md" | "lg" }>(
  function Input({ className, invalid, prefixIcon, suffix, inputSize = "md", ...rest }, ref) {
    const h = { sm: "h-7", md: "h-9", lg: "h-10" }[inputSize];
    return (
      <div className={clsx("relative flex items-center", className)}>
        {prefixIcon && <span className="pointer-events-none absolute left-3 text-fg-muted [&_svg]:size-4">{prefixIcon}</span>}
        <input ref={ref} aria-invalid={invalid || undefined}
          className={clsx(inputCls, h, "px-3 text-[14px]", prefixIcon && "pl-9", suffix && "pr-12", invalid ? "border-danger" : "border-line-strong")} {...rest} />
        {suffix && <span className="pointer-events-none absolute right-3 text-[13px] text-fg-muted">{suffix}</span>}
      </div>
    );
  },
);

export const Textarea = forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement> & { invalid?: boolean; autoGrow?: boolean; maxHeight?: number }>(
  function Textarea({ className, invalid, autoGrow, maxHeight = 320, onChange, ...rest }, ref) {
    return (
      <textarea ref={ref} aria-invalid={invalid || undefined}
        className={clsx(inputCls, "block min-h-[120px] px-3 py-2 text-[14px] leading-5", invalid ? "border-danger" : "border-line-strong", className)}
        onChange={(e) => {
          if (autoGrow) {
            e.currentTarget.style.height = "auto";
            e.currentTarget.style.height = Math.min(maxHeight, e.currentTarget.scrollHeight + 2) + "px";
          }
          onChange?.(e);
        }}
        {...rest} />
    );
  },
);

export function Select({ value, onChange, options, className, id, size = "md", ariaLabel, disabled }:
  { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; className?: string; id?: string; size?: "sm" | "md"; ariaLabel?: string; disabled?: boolean }) {
  return (
    <div className={clsx("relative", className)}>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} aria-label={ariaLabel} disabled={disabled}
        className={clsx(inputCls, "appearance-none border-line-strong pr-9 pl-3 text-[14px]", size === "sm" ? "h-7 text-[13px]" : "h-9")}>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <ChevronDown className="pointer-events-none absolute top-1/2 right-2.5 size-4 -translate-y-1/2 text-fg-muted" />
    </div>
  );
}

export function Checkbox({ checked, onChange, label, indeterminate, id, disabled, description }:
  { checked: boolean; onChange: (v: boolean) => void; label?: React.ReactNode; indeterminate?: boolean; id?: string; disabled?: boolean; description?: React.ReactNode }) {
  const auto = useId();
  const cid = id ?? auto;
  return (
    <label htmlFor={cid} className={clsx("inline-flex cursor-pointer items-start gap-2 select-none", disabled && "cursor-not-allowed opacity-60")}>
      <span className="relative mt-0.5 grid size-4 shrink-0 place-items-center">
        <input id={cid} type="checkbox" className="peer absolute inset-0 appearance-none rounded-xs border border-line-hover bg-surface checked:border-accent checked:bg-accent indeterminate:border-accent indeterminate:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--focus-ring)]"
          checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)}
          ref={(el) => { if (el) el.indeterminate = !!indeterminate; }} />
        {checked && !indeterminate && <Check className="pointer-events-none relative size-3 text-white" strokeWidth={3} />}
        {indeterminate && <span className="pointer-events-none relative h-0.5 w-2 bg-white" />}
      </span>
      {(label || description) && (
        <span>
          {label && <span className="text-[14px] text-fg">{label}</span>}
          {description && <span className="block text-caption text-fg-muted">{description}</span>}
        </span>
      )}
    </label>
  );
}

export function Radio({ checked, onChange, label, name, value }: { checked: boolean; onChange: (v: string) => void; label: React.ReactNode; name: string; value: string }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2">
      <input type="radio" name={name} value={value} checked={checked} onChange={() => onChange(value)}
        className="size-4 appearance-none rounded-full border border-line-hover bg-surface checked:border-[5px] checked:border-accent" />
      <span className="text-[14px]">{label}</span>
    </label>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label?: React.ReactNode; disabled?: boolean }) {
  return (
    <label className={clsx("inline-flex cursor-pointer items-center gap-2", disabled && "cursor-not-allowed opacity-60")}>
      <button type="button" role="switch" aria-checked={checked} disabled={disabled} onClick={() => onChange(!checked)}
        className={clsx("relative h-[18px] w-8 shrink-0 rounded-full transition-colors duration-[var(--motion-fast)]", checked ? "bg-accent" : "bg-[var(--g-300)] dark:bg-[var(--g-600)]")}>
        <span className={clsx("absolute top-[2px] size-[14px] rounded-full bg-white transition-transform duration-[var(--motion-fast)]", checked ? "translate-x-[16px]" : "translate-x-[2px]")} />
      </button>
      {label && <span className="text-[14px]">{label}</span>}
    </label>
  );
}

/** Segmented control: 2–4 mutually exclusive options (radio group). */
export function Segmented<T extends string>({ value, onChange, options, ariaLabel, size = "md", className }:
  { value: T; onChange: (v: T) => void; options: { value: T; label: React.ReactNode; icon?: React.ReactNode }[]; ariaLabel: string; size?: "sm" | "md"; className?: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const idx = options.findIndex((o) => o.value === value);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    e.preventDefault();
    const n = (idx + (e.key === "ArrowRight" ? 1 : -1) + options.length) % options.length;
    onChange(options[n].value);
    refs.current[n]?.focus();
  };
  return (
    <div role="radiogroup" aria-label={ariaLabel} onKeyDown={onKey}
      className={clsx("inline-flex shrink-0 rounded-sm bg-subtle p-[2px]", size === "sm" ? "h-7" : "h-8", className)}>
      {options.map((o, i) => (
        <button key={o.value} ref={(el) => { refs.current[i] = el; }} type="button" role="radio" aria-checked={o.value === value} tabIndex={o.value === value ? 0 : -1}
          onClick={() => onChange(o.value)}
          className={clsx("inline-flex items-center gap-1.5 rounded-sm px-3 text-[13px] font-semibold whitespace-nowrap transition-colors [&_svg]:size-4",
            o.value === value ? "border border-line bg-surface text-fg" : "border border-transparent text-fg-muted hover:text-fg")}>
          {o.icon}
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Multi-select with chips inside the field; "+N" after 3. */
export function MultiSelect({ values, onChange, options, placeholder = "Select…", id, invalid, ariaLabel }:
  { values: string[]; onChange: (v: string[]) => void; options: { value: string; label: string; hint?: string; color?: string }[]; placeholder?: string; id?: string; invalid?: boolean; ariaLabel?: string }) {
  const [q, setQ] = useState("");
  const sel = options.filter((o) => values.includes(o.value));
  const filtered = options.filter((o) => o.label.toLowerCase().includes(q.toLowerCase()));
  const toggle = (v: string) => onChange(values.includes(v) ? values.filter((x) => x !== v) : [...values, v]);
  return (
    <Popover label={ariaLabel} width={320} align="end" trigger={(p) => (
      <div className={clsx(inputCls, "flex min-h-9 items-center gap-1 py-1 pr-1 pl-2", invalid ? "border-danger" : "border-line-strong")}
        onClick={(e) => { if (e.target === e.currentTarget) p.onClick(); }}>
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1" onClick={(e) => { if (e.target === e.currentTarget) p.onClick(); }}>
          {sel.length === 0 && <span className="px-1 text-fg-faint" onClick={p.onClick}>{placeholder}</span>}
          {sel.slice(0, 3).map((o) => (
            <Chip key={o.value} dot={o.color} onRemove={() => toggle(o.value)}>{o.label}</Chip>
          ))}
          {sel.length > 3 && <span className="text-[13px] text-fg-muted">+{sel.length - 3}</span>}
        </div>
        <button ref={p.ref} onClick={p.onClick} aria-expanded={p["aria-expanded"]} aria-haspopup="listbox" id={id} type="button"
          aria-label={`${ariaLabel ?? "Options"}: ${sel.map((o) => o.label).join(", ") || "none selected"}`}
          className="grid size-7 shrink-0 place-items-center rounded-sm text-fg-muted hover:bg-subtle">
          <ChevronDown className="size-4" />
        </button>
      </div>
    )}>
      <div className="p-2">
        {options.length > 6 && <Input autoFocus inputSize="sm" prefixIcon={<Search />} placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} className="mb-2" />}
        {options.length > 8 && (
          <div className="border-b border-line pb-1 mb-1 px-1">
            <Checkbox checked={values.length === options.length} indeterminate={values.length > 0 && values.length < options.length}
              onChange={(v) => onChange(v ? options.map((o) => o.value) : [])} label="Select all" />
          </div>
        )}
        <div className="max-h-[280px] overflow-y-auto">
          {filtered.map((o) => (
            <div key={o.value} className="flex h-8 items-center rounded-sm px-1 hover:bg-subtle">
              <Checkbox checked={values.includes(o.value)} onChange={() => toggle(o.value)}
                label={<span className="inline-flex items-center gap-2">{o.color && <span className="size-2 rounded-full" style={{ background: o.color }} />}{o.label}{o.hint && <span className="text-caption text-fg-muted">{o.hint}</span>}</span>} />
            </div>
          ))}
          {!filtered.length && <div className="px-2 py-1.5 text-fg-muted">No matches for &apos;{q}&apos;</div>}
        </div>
      </div>
    </Popover>
  );
}

/** Chip input for URLs, tags and exclusion lists. */
export function ChipInput({ values, onChange, validate, placeholder, id }:
  { values: string[]; onChange: (v: string[]) => void; validate?: (v: string) => string | null; placeholder?: string; id?: string }) {
  const [draft, setDraft] = useState("");
  const [armed, setArmed] = useState(false);
  const add = (raw: string) => {
    const parts = raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    if (!parts.length) return;
    onChange(Array.from(new Set([...values, ...parts])));
    setDraft("");
  };
  return (
    <div className={clsx(inputCls, "flex min-h-9 flex-wrap items-center gap-1 border-line-strong px-2 py-1 focus-within:border-accent")}>
      {values.map((v) => {
        const err = validate?.(v);
        return (
          <span key={v} title={err ?? undefined}>
            <Chip className={err ? "!bg-danger-soft !text-danger outline outline-1 outline-[var(--danger-border)]" : ""} onRemove={() => onChange(values.filter((x) => x !== v))}>{v}</Chip>
          </span>
        );
      })}
      <input id={id} value={draft} placeholder={values.length ? "" : placeholder}
        className="min-w-[160px] flex-1 bg-transparent px-1 text-[14px] outline-none placeholder:text-fg-faint"
        onChange={(e) => { setDraft(e.target.value); setArmed(false); }}
        onPaste={(e) => { const t = e.clipboardData.getData("text"); if (/[\s,]/.test(t.trim())) { e.preventDefault(); add(draft + t); } }}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") { e.preventDefault(); add(draft); }
          else if (e.key === "Backspace" && !draft && values.length) {
            if (armed) { onChange(values.slice(0, -1)); setArmed(false); } else setArmed(true);
          }
        }}
        onBlur={() => add(draft)} />
    </div>
  );
}
