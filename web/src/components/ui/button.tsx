"use client";

import clsx from "clsx";
import Link from "next/link";
import { forwardRef } from "react";
import { Check, ChevronDown, Copy } from "lucide-react";
import { useState } from "react";
import { copyText } from "@/lib/hooks";
import { Spinner } from "./feedback";
import { Tooltip } from "./overlay";

type Variant = "primary" | "secondary" | "tertiary" | "danger" | "danger-secondary" | "icon";
type Size = "sm" | "md" | "lg";

const base =
  "inline-flex items-center justify-center gap-2 whitespace-nowrap font-semibold select-none rounded-sm " +
  "transition-colors duration-[var(--motion-fast)] ease-[var(--ease-standard)] disabled:cursor-not-allowed";

const variants: Record<Variant, string> = {
  primary: "bg-[var(--btn-primary)] text-white hover:bg-[var(--btn-primary-hover)] active:bg-[var(--btn-primary-pressed)]",
  secondary: "bg-surface text-fg border border-line-strong hover:bg-subtle hover:border-line-hover active:bg-[var(--g-100)] dark:active:bg-subtle",
  tertiary: "bg-transparent text-accent-text hover:bg-accent-soft active:bg-accent-soft-2",
  danger: "bg-[var(--danger)] text-white hover:bg-[var(--danger-hover)] active:bg-[var(--danger-pressed)]",
  "danger-secondary": "bg-surface text-danger border border-danger-line hover:bg-danger-soft",
  icon: "bg-transparent text-fg-muted hover:bg-subtle hover:text-fg active:bg-[var(--g-100)]",
};
const disabledCls = "!bg-[var(--disabled-bg)] !text-[var(--disabled-text)] !border-transparent";

const sizes: Record<Size, string> = {
  sm: "h-7 px-2.5 text-[13px] [&_svg]:size-4",
  md: "h-9 px-3.5 text-[14px] [&_svg]:size-5",
  lg: "h-10 px-[18px] text-[14px] [&_svg]:size-5",
};
const iconSizes: Record<Size, string> = { sm: "size-7 [&_svg]:size-4", md: "size-9 [&_svg]:size-5", lg: "size-10 [&_svg]:size-5" };

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: React.ReactNode;
  disabledReason?: string;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, icon, className, children, disabled, disabledReason, ...rest },
  ref,
) {
  const btn = (
    <button
      ref={ref}
      className={clsx(base, variant === "icon" ? iconSizes[size] : sizes[size], variants[variant], disabled && variant !== "icon" && disabledCls, className)}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading ? <Spinner size={16} /> : icon}
      {children}
    </button>
  );
  if (disabled && disabledReason) return <Tooltip content={disabledReason}><span className="inline-flex">{btn}</span></Tooltip>;
  return btn;
});

export function IconButton({ label, size = "md", children, className, ...rest }: Omit<ButtonProps, "variant"> & { label: string }) {
  return (
    <Tooltip content={label}>
      <Button variant="icon" size={size} aria-label={label} className={className} {...rest}>
        {children}
      </Button>
    </Tooltip>
  );
}

export function ButtonLink({ href, variant = "secondary", size = "md", icon, children, className, ...rest }:
  { href: string; variant?: Variant; size?: Size; icon?: React.ReactNode; children?: React.ReactNode; className?: string } & Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, "href">) {
  return (
    <Link href={href} className={clsx(base, sizes[size], variants[variant], className)} {...rest}>
      {icon}
      {children}
    </Link>
  );
}

/** Copy action with a 1.5 s "Copied" confirmation. */
export function CopyButton({ text, label = "Copy", copiedLabel = "Copied", size = "sm", iconOnly, onCopied, variant = "secondary" }:
  { text: string | (() => string); label?: string; copiedLabel?: string; size?: Size; iconOnly?: boolean; onCopied?: () => void; variant?: Variant }) {
  const [done, setDone] = useState(false);
  const run = async () => {
    await copyText(typeof text === "function" ? text() : text);
    setDone(true);
    onCopied?.();
    setTimeout(() => setDone(false), 1500);
  };
  if (iconOnly)
    return (
      <IconButton label={done ? copiedLabel : label} size={size} onClick={run}>
        {done ? <Check className="text-success" /> : <Copy />}
      </IconButton>
    );
  return (
    <Button size={size} variant={variant} onClick={run} icon={done ? <Check /> : <Copy />} className="min-w-[96px]">
      {done ? copiedLabel : label}
    </Button>
  );
}

export function ButtonGroup({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={clsx("inline-flex [&>*:not(:first-child)]:-ml-px [&>*]:rounded-none [&>*:first-child]:rounded-l-sm [&>*:last-child]:rounded-r-sm", className)}>
      {children}
    </div>
  );
}

export function SplitButton({ label, onClick, menu, loading, variant = "secondary" }:
  { label: React.ReactNode; onClick: () => void; menu: React.ReactNode; loading?: boolean; variant?: Variant }) {
  return (
    <ButtonGroup>
      <Button variant={variant} onClick={onClick} loading={loading}>{label}</Button>
      {menu}
    </ButtonGroup>
  );
}

export const ChevronDownIcon = ChevronDown;
