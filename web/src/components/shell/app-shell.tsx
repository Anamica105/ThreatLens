"use client";

import clsx from "clsx";
import {
  Bell, Bug, CircleHelp, Code, Download, Fingerprint, LayoutDashboard, Menu as MenuIcon, Moon, Pin, PinOff,
  Plus, Search, Settings, Sun, SunMoon, UserRoundSearch, Files, Keyboard, UserCog, X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { useApp, useWsHref } from "../providers";
import { Avatar, Kbd } from "../ui/badges";
import { ButtonLink } from "../ui/button";
import { Dialog, Menu, Popover, Tooltip } from "../ui/overlay";
import { CommandPalette } from "./command-palette";
import { WorkspaceSwitcher } from "./workspace-switcher";
import { useLocalStorage, useApi } from "@/lib/hooks";
import { relative } from "@/lib/format";
import { post } from "@/lib/api";
import { threadHref, type NotificationsResponse } from "../research/comments/model";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, key: "d" },
  { href: "/research", label: "Research", icon: Files, key: "r" },
  { group: "Libraries" },
  { href: "/library/actors", label: "Threat actors", icon: UserRoundSearch, key: "a" },
  { href: "/library/malware", label: "Malware & tools", icon: Bug, key: "m" },
  { href: "/library/queries", label: "Detection queries", icon: Code, key: "q" },
  { href: "/library/iocs", label: "IoCs", icon: Fingerprint, key: "i" },
  { group: "" },
  { href: "/exports", label: "Exports", icon: Download, key: "e" },
] as const;

const RAIL = 64;
const EXPANDED = 240;
const OPEN_DELAY = 150;
const CLOSE_DELAY = 220;

function useMedia(query: string) {
  const [match, setMatch] = useState(false);
  useEffect(() => {
    const m = window.matchMedia(query);
    const on = () => setMatch(m.matches);
    on();
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, [query]);
  return match;
}

/**
 * Navigation rail (design.md 9.2, refined): a 64 px icon rail that expands to 240 px as an overlay on hover or keyboard
 * focus, without reflowing the page. Users can pin it open (remembered); pinned on lg+ pads the content instead.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const [pinned, setPinned] = useLocalStorage("tl.rail.pinned", false);
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const wsHref = useWsHref();
  const searchRef = useRef<HTMLInputElement | null>(null);
  const gPending = useRef<number>(0);
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isLg = useMedia("(min-width: 1024px)");
  const pinnedActive = pinned && isLg;
  const expanded = mobileOpen || pinnedActive || hovered || focused || menuOpen;
  const overlaying = expanded && !pinnedActive && !mobileOpen;

  useEffect(() => setMobileOpen(false), [pathname]);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => () => { if (hoverTimer.current) clearTimeout(hoverTimer.current); }, []);

  const onEnter = useCallback(() => {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    hoverTimer.current = setTimeout(() => setHovered(true), OPEN_DELAY);
  }, []);
  const onLeave = useCallback(() => {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    hoverTimer.current = setTimeout(() => setHovered(false), CLOSE_DELAY);
  }, []);
  // Keyboard focus expands the rail; mouse clicks don't (hover already handles those).
  const onFocusIn = (e: React.FocusEvent) => {
    if ((e.target as HTMLElement).matches(":focus-visible")) setFocused(true);
  };
  const onFocusOut = (e: React.FocusEvent<HTMLElement>) => {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocused(false);
  };
  const onMenuOpenChange = useCallback((o: boolean) => {
    setMenuOpen(o);
    if (!o) setHovered(false);
  }, []);

  // Global keyboard shortcuts (design.md 28)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      const typing = t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "/") {
        e.preventDefault();
        setPaletteOpen(true);
      } else if (e.key === "?") {
        setShortcutsOpen(true);
      } else if (e.key === "n") {
        router.push(wsHref("/research/new"));
      } else if (e.key === "g") {
        gPending.current = Date.now();
      } else if (Date.now() - gPending.current < 1200) {
        const item = NAV.find((n) => "key" in n && n.key === e.key);
        if (item && "href" in item) router.push(wsHref(item.href));
        gPending.current = 0;
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [router, wsHref]);

  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[1500] focus:rounded-sm focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>
      {/* Content offset used by fixed bars on other pages (sticky footers, compact headers). */}
      <style>{`:root{--sb:${pinned ? EXPANDED : RAIL}px}
        @media (min-width: 640px){ .tl-main{ padding-left:${RAIL}px } }
        @media (min-width: 1024px){ .tl-main{ padding-left:var(--sb) } }`}</style>
      {mobileOpen && <div className="fixed inset-0 z-[205] sm:hidden" style={{ background: "var(--scrim)" }} onClick={() => setMobileOpen(false)} />}
      <nav aria-label="Main" data-expanded={expanded || undefined}
        onMouseEnter={mobileOpen ? undefined : onEnter} onMouseLeave={mobileOpen ? undefined : onLeave} onFocus={onFocusIn} onBlur={onFocusOut}
        className={clsx(
          "fixed top-0 bottom-0 left-0 z-[210] flex flex-col overflow-hidden border-r border-line bg-surface",
          "transition-[width,transform,box-shadow] duration-[var(--motion-base)] ease-[var(--ease-standard)]",
          mobileOpen ? "translate-x-0" : "-translate-x-full sm:translate-x-0",
          (overlaying || mobileOpen) && "shadow-elev-rail",
        )}
        style={{ width: expanded ? EXPANDED : RAIL }}>
        <RailInner expanded={expanded} mobile={mobileOpen} pinned={pinned} canPin={isLg} onPin={() => { setPinned(!pinned); setHovered(false); }}
          onShortcuts={() => setShortcutsOpen(true)} onClose={() => setMobileOpen(false)} onMenuOpenChange={onMenuOpenChange} />
      </nav>

      <div className="tl-main transition-[padding] duration-[var(--motion-base)] ease-[var(--ease-standard)]">
        {/* Top bar */}
        <header className={clsx("sticky top-0 z-[200] flex h-14 items-center gap-3 border-b border-line bg-surface px-3 md:px-4", scrolled && "shadow-elev-1")}>
          <button className="grid size-9 shrink-0 place-items-center rounded-sm text-fg-muted hover:bg-subtle sm:hidden" aria-label="Open menu" onClick={() => setMobileOpen(true)}>
            <MenuIcon className="size-5" />
          </button>
          <div className="min-w-0 shrink"><WorkspaceSwitcher /></div>
          <button onClick={() => setPaletteOpen(true)}
            className="hidden h-9 max-w-[480px] min-w-0 flex-1 items-center gap-2 rounded-sm border border-line-strong bg-surface px-3 text-left text-fg-faint transition-colors hover:border-line-hover md:flex">
            <Search className="size-4 shrink-0 text-fg-muted" />
            <span className="flex-1 truncate text-[14px]">Search research, IoCs, actors…</span>
            <Kbd>/</Kbd>
          </button>
          <div className="flex-1 md:hidden" />
          <button className="grid size-9 shrink-0 place-items-center rounded-sm text-fg-muted hover:bg-subtle md:hidden" aria-label="Search" onClick={() => setPaletteOpen(true)}>
            <Search className="size-5" />
          </button>
          <div className="hidden flex-1 md:block" />
          <ButtonLink href={wsHref("/research/new")} variant="primary" icon={<Plus />} className="shrink-0 max-sm:hidden">New research</ButtonLink>
          <Notifications />
          <Tooltip content="Keyboard shortcuts and help">
            <button className="grid size-9 shrink-0 place-items-center rounded-sm text-fg-muted hover:bg-subtle" aria-label="Help" onClick={() => setShortcutsOpen(true)}>
              <CircleHelp className="size-5" />
            </button>
          </Tooltip>
        </header>
        <main id="main" tabIndex={-1} className="min-w-0 outline-none">{children}</main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} inputRef={searchRef} />
      <ShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
}

/** Label that fades with the rail; never wraps or reflows while the width animates. */
function RailLabel({ show, children, className }: { show: boolean; children: React.ReactNode; className?: string }) {
  return (
    <span aria-hidden={!show || undefined}
      className={clsx("min-w-0 flex-1 truncate whitespace-nowrap transition-opacity duration-[var(--motion-fast)]", show ? "opacity-100 delay-75" : "opacity-0", className)}>
      {children}
    </span>
  );
}

function RailInner({ expanded, mobile, pinned, canPin, onPin, onShortcuts, onClose, onMenuOpenChange }:
  { expanded: boolean; mobile: boolean; pinned: boolean; canPin: boolean; onPin: () => void; onShortcuts: () => void; onClose: () => void; onMenuOpenChange: (o: boolean) => void }) {
  const pathname = usePathname();
  const wsHref = useWsHref();
  const { user, meta, theme, setTheme, switchUser } = useApp();
  const active = (href: string) => pathname === href || pathname.startsWith(href + "/");
  // Icon sits at a fixed x (22 px) in both states, so nothing jumps while the width animates.
  const item = (href: string, label: string, Icon: React.ComponentType<{ className?: string }>) => (
    <li key={href}>
      <Link href={wsHref(href)} aria-current={active(href) ? "page" : undefined} aria-label={expanded ? undefined : label}
        className={clsx("group/item flex h-9 items-center gap-3 overflow-hidden rounded-sm px-2.5 text-[14px] whitespace-nowrap transition-colors duration-[var(--motion-instant)] [&_svg]:size-5 [&_svg]:shrink-0",
          active(href) ? "bg-accent-soft font-semibold text-accent-text" : "text-fg-muted hover:bg-subtle hover:text-fg")}>
        <Icon />
        <RailLabel show={expanded}>{label}</RailLabel>
      </Link>
    </li>
  );
  return (
    <>
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-line pr-2 pl-5">
        <Logo />
        <RailLabel show={expanded} className="text-[16px] font-bold tracking-[-0.01em] text-fg">ThreatLens</RailLabel>
        {mobile ? (
          <button onClick={onClose} className="grid size-8 shrink-0 place-items-center rounded-sm hover:bg-subtle" aria-label="Close menu"><X className="size-5" /></button>
        ) : canPin && (
          <Tooltip content={pinned ? "Unpin sidebar" : "Keep sidebar open"} side="bottom">
            <button onClick={onPin} aria-pressed={pinned} aria-label={pinned ? "Unpin sidebar" : "Pin sidebar open"} tabIndex={expanded ? 0 : -1}
              className={clsx("grid size-8 shrink-0 place-items-center rounded-sm transition-[opacity,background-color] duration-[var(--motion-fast)] [&_svg]:size-4",
                pinned ? "text-accent-text hover:bg-accent-soft" : "text-fg-muted hover:bg-subtle hover:text-fg",
                expanded ? "opacity-100" : "pointer-events-none opacity-0")}>
              {pinned ? <PinOff /> : <Pin />}
            </button>
          </Tooltip>
        )}
      </div>
      <ul className="flex-1 space-y-0.5 overflow-x-hidden overflow-y-auto p-3">
        {NAV.map((n, i) =>
          "group" in n ? (
            <li key={i} aria-hidden={!n.group || !expanded || undefined} className="relative h-8">
              <span className={clsx("absolute inset-x-1 top-1/2 h-px bg-[var(--border-subtle)] transition-opacity duration-[var(--motion-fast)]", expanded && n.group ? "opacity-0" : "opacity-100")} />
              {n.group && (
                <span className={clsx("absolute bottom-1 left-2.5 text-caption font-semibold whitespace-nowrap text-fg-muted transition-opacity duration-[var(--motion-fast)]", expanded ? "opacity-100 delay-75" : "opacity-0")}>{n.group}</span>
              )}
            </li>
          ) : item(n.href, n.label, n.icon),
        )}
      </ul>
      <div className="shrink-0 space-y-0.5 border-t border-line p-3">
        <ul>{item("/settings", "Settings", Settings)}</ul>
        <Menu align="start" width={240} onOpenChange={onMenuOpenChange} items={[
          ...((meta?.users ?? []).filter((u) => u.id !== user?.id).map((u) => ({ label: `Sign in as ${u.name} (${u.role})`, icon: <UserCog />, onSelect: () => switchUser(u.id) }))),
          { label: "", divider: true, onSelect: () => undefined },
          { label: "Theme: Light", icon: <Sun />, onSelect: () => setTheme("light"), shortcut: theme === "light" ? "✓" : "" },
          { label: "Theme: Night shift", icon: <Moon />, onSelect: () => setTheme("dark"), shortcut: theme === "dark" ? "✓" : "" },
          { label: "Theme: System", icon: <SunMoon />, onSelect: () => setTheme("system"), shortcut: theme === "system" ? "✓" : "" },
          { label: "", divider: true, onSelect: () => undefined },
          { label: "Keyboard shortcuts", icon: <Keyboard />, onSelect: onShortcuts, shortcut: "?" },
        ]} trigger={(p) => (
          <button {...p} className="flex h-11 w-full items-center gap-3 overflow-hidden rounded-sm px-1.5 text-left whitespace-nowrap hover:bg-subtle" aria-label="User menu">
            <Avatar initials={user?.initials} size={28} />
            <span className={clsx("min-w-0 flex-1 transition-opacity duration-[var(--motion-fast)]", expanded ? "opacity-100 delay-75" : "opacity-0")}>
              <span className="block truncate text-[14px] font-semibold">{user?.name ?? "…"}</span>
              <span className="block truncate text-caption text-fg-muted">{user ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : ""}</span>
            </span>
          </button>
        )} />
      </div>
    </>
  );
}

export function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden className="shrink-0">
      <rect x="1" y="1" width="22" height="22" rx="6" fill="var(--btn-primary)" />
      <circle cx="10.5" cy="10.5" r="4.6" fill="none" stroke="#fff" strokeWidth="2" />
      <path d="M14 14l4.2 4.2" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" />
      <path d="M8.2 10.5h4.6" stroke="#C9C5EC" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

/** Top-bar bell: @mentions and replies on comment threads (unread dot), then recent research activity. */
function Notifications() {
  const { user } = useApp();
  const { data } = useApi<{ recent: { id: string; title: string; status: string; updated_at: string }[] }>("/api/dashboard?period=quarter", { interval: 60000 });
  const { data: notes, reload } = useApi<NotificationsResponse>(user ? `/api/research/notifications?u=${user.id}` : null, { interval: 30000 });
  const wsHref = useWsHref();
  const items = data?.recent ?? [];
  const mentions = notes?.items ?? [];
  const unread = notes?.unread ?? 0;
  const markRead = async (ids: number[]) => {
    try { await post("/api/research/notifications/read", { ids }); await reload(); } catch { /* best effort */ }
  };
  return (
    <Popover align="end" width={360} label="Notifications" trigger={(p) => (
      <button {...p} className="relative grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-subtle"
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}>
        <Bell className="size-5" />
        {(unread > 0 || items.some((i) => i.status === "in_review")) && <span className={clsx("absolute top-2 right-2 size-2 rounded-full", unread > 0 ? "bg-danger" : "bg-accent")} />}
      </button>
    )}>
      {(close) => (
        <div className="max-h-[70vh] overflow-y-auto p-2">
          <div className="flex items-center justify-between px-2 py-1">
            <span className="text-h4 font-semibold">Mentions{unread > 0 && <span className="ml-1.5 rounded-full bg-danger px-1.5 text-caption font-semibold text-white tabular">{unread}</span>}</span>
            {unread > 0 && <button type="button" onClick={() => markRead([])} className="text-caption font-semibold text-accent-text hover:underline">Mark all read</button>}
          </div>
          {mentions.length === 0 && <p className="px-2 py-2 text-body-sm text-fg-muted">No mentions yet.</p>}
          {mentions.slice(0, 8).map((n) => (
            <Link key={n.id} onClick={() => { if (!n.read) markRead([n.id]); close(); }}
              href={wsHref(threadHref(n.research_id, n.section, n.comment_id))}
              className={clsx("flex gap-2 rounded-sm px-2 py-2 hover:bg-subtle", !n.read && "bg-accent-soft")}>
              <Avatar initials={n.by?.initials} size={24} />
              <span className="min-w-0 flex-1">
                <span className="block text-[14px]">
                  <span className="font-semibold">{n.by?.name ?? "Someone"}</span> {n.kind === "reply" ? "replied" : "mentioned you"} on <span className="font-semibold">{n.section_label}</span> · <span className="font-mono text-mono-sm">{n.research_id}</span>
                </span>
                <span className="block truncate text-caption text-fg-muted">{n.message}</span>
                <span className="block text-caption text-fg-muted">{relative(n.created_at)}</span>
              </span>
              {!n.read && <span className="mt-2 size-2 shrink-0 rounded-full bg-danger" aria-label="Unread" />}
            </Link>
          ))}
          <div className="mt-1 border-t border-line px-2 pt-2 pb-1 text-h4 font-semibold">Recent activity</div>
          {items.length === 0 && <p className="px-2 py-3 text-fg-muted">Nothing new.</p>}
          {items.slice(0, 6).map((i) => (
            <Link key={i.id} href={wsHref(`/research/${i.id}`)} onClick={close} className="block rounded-sm px-2 py-2 hover:bg-subtle">
              <div className="truncate text-[14px]">{i.title}</div>
              <div className="text-caption text-fg-muted"><span className="font-mono">{i.id}</span> · {i.status.replace("_", " ")} · {relative(i.updated_at)}</div>
            </Link>
          ))}
        </div>
      )}
    </Popover>
  );
}

function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const rows: [React.ReactNode, string][] = [
    [<Kbd key="s">/</Kbd>, "Search"],
    [<span key="k" className="flex gap-1"><Kbd>Ctrl</Kbd><Kbd>K</Kbd></span>, "Command palette (switch workspace, actions)"],
    [<Kbd key="n">n</Kbd>, "New research"],
    [<span key="g" className="flex gap-1"><Kbd>g</Kbd><Kbd>d</Kbd></span>, "Go to Dashboard (r Research, a Actors, m Malware, q Queries, i IoCs, e Exports)"],
    [<span key="1" className="flex gap-1"><Kbd>1</Kbd>–<Kbd>8</Kbd></span>, "Switch tab on Research details"],
    [<Kbd key="c">c</Kbd>, "Copy the focused query or IoC"],
    [<Kbd key="q">?</Kbd>, "Show this dialog"],
  ];
  return (
    <Dialog open={open} onClose={onClose} title="Keyboard shortcuts" size="md">
      <table className="w-full">
        <tbody>
          {rows.map(([k, d], i) => (
            <tr key={i} className="border-b border-line last:border-0">
              <td className="w-40 py-2.5">{k}</td>
              <td className="py-2.5 text-fg-strong">{d}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Dialog>
  );
}
