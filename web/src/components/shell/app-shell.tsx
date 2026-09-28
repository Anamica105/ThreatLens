"use client";

import clsx from "clsx";
import {
  Bell, Bug, ChevronsLeft, ChevronsRight, CircleHelp, Code, Download, Fingerprint, LayoutDashboard, Menu as MenuIcon, Moon,
  Plus, Search, Settings, Sun, SunMoon, UserRoundSearch, Files, Keyboard, UserCog, X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useApp, useWsHref } from "../providers";
import { Avatar, Kbd } from "../ui/badges";
import { ButtonLink } from "../ui/button";
import { Dialog, Menu, Popover, Tooltip } from "../ui/overlay";
import { CommandPalette } from "./command-palette";
import { WorkspaceSwitcher } from "./workspace-switcher";
import { useLocalStorage, useApi } from "@/lib/hooks";
import { relative } from "@/lib/format";

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

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useLocalStorage("tl.sidebar.collapsed", false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const wsHref = useWsHref();
  const searchRef = useRef<HTMLInputElement | null>(null);
  const gPending = useRef<number>(0);

  useEffect(() => setMobileOpen(false), [pathname]);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
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

  const sidebarWidth = collapsed ? 64 : 240;

  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[1500] focus:rounded-sm focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>
      {/* Sidebar */}
      {mobileOpen && <div className="fixed inset-0 z-[190] sm:hidden" style={{ background: "var(--scrim)" }} onClick={() => setMobileOpen(false)} />}
      <nav aria-label="Main"
        className={clsx("fixed top-0 bottom-0 left-0 z-[200] flex flex-col border-r border-line bg-surface transition-[width,transform] duration-[var(--motion-base)]",
          mobileOpen ? "translate-x-0" : "-translate-x-full sm:translate-x-0")}
        style={{ width: mobileOpen ? 240 : undefined }}>
        <SidebarInner collapsed={collapsed && !mobileOpen} onToggle={() => setCollapsed(!collapsed)} onShortcuts={() => setShortcutsOpen(true)}
          onClose={() => setMobileOpen(false)} mobile={mobileOpen} />
      </nav>
      <style>{`:root{--sb:${sidebarWidth}px} @media (min-width: 640px){ nav[aria-label="Main"]{ width:64px } } @media (min-width: 1024px){ nav[aria-label="Main"]{ width:${sidebarWidth}px } }
        @media (min-width: 640px){ .tl-main{ padding-left:64px } } @media (min-width: 1024px){ .tl-main{ padding-left:${sidebarWidth}px } }`}</style>

      <div className="tl-main transition-[padding] duration-[var(--motion-base)]">
        {/* Top bar */}
        <header className={clsx("sticky top-0 z-[200] flex h-14 items-center gap-3 border-b border-line bg-surface px-3 md:px-4", scrolled && "shadow-elev-1")}>
          <button className="grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-subtle sm:hidden" aria-label="Open menu" onClick={() => setMobileOpen(true)}>
            <MenuIcon className="size-5" />
          </button>
          <WorkspaceSwitcher />
          <button onClick={() => setPaletteOpen(true)}
            className="hidden h-9 max-w-[480px] flex-1 items-center gap-2 rounded-sm border border-line-strong bg-surface px-3 text-left text-fg-faint hover:border-line-hover md:flex">
            <Search className="size-4 text-fg-muted" />
            <span className="flex-1 truncate text-[14px]">Search research, IoCs, actors…</span>
            <Kbd>/</Kbd>
          </button>
          <div className="flex-1 md:hidden" />
          <button className="grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-subtle md:hidden" aria-label="Search" onClick={() => setPaletteOpen(true)}>
            <Search className="size-5" />
          </button>
          <div className="hidden flex-1 md:block" />
          <ButtonLink href={wsHref("/research/new")} variant="primary" icon={<Plus />} className="hidden sm:inline-flex">New research</ButtonLink>
          <Notifications />
          <Tooltip content="Keyboard shortcuts and help">
            <button className="grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-subtle" aria-label="Help" onClick={() => setShortcutsOpen(true)}>
              <CircleHelp className="size-5" />
            </button>
          </Tooltip>
        </header>
        <main id="main" tabIndex={-1} className="outline-none">{children}</main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} inputRef={searchRef} />
      <ShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
}

function SidebarInner({ collapsed, onToggle, onShortcuts, onClose, mobile }: { collapsed: boolean; onToggle: () => void; onShortcuts: () => void; onClose: () => void; mobile: boolean }) {
  const pathname = usePathname();
  const wsHref = useWsHref();
  const { user, meta, theme, setTheme, switchUser } = useApp();
  const active = (href: string) => pathname === href || pathname.startsWith(href + "/");
  const item = (href: string, label: string, Icon: React.ComponentType<{ className?: string }>) => {
    const link = (
      <Link href={wsHref(href)} aria-current={active(href) ? "page" : undefined}
        className={clsx("flex h-9 items-center gap-3 rounded-sm px-3 text-[14px] transition-colors [&_svg]:size-5 [&_svg]:shrink-0",
          active(href) ? "bg-accent-soft font-semibold text-accent-text" : "text-fg-muted hover:bg-subtle hover:text-fg", collapsed && "justify-center px-0")}>
        <Icon />
        {!collapsed && <span className="truncate">{label}</span>}
      </Link>
    );
    return <li key={href}>{collapsed ? <Tooltip content={label}>{link}</Tooltip> : link}</li>;
  };
  return (
    <>
      <div className={clsx("flex h-14 items-center gap-2 border-b border-line px-4", collapsed && "justify-center px-0")}>
        <Logo />
        {!collapsed && <span className="text-[16px] font-bold tracking-[-0.01em]">ThreatLens</span>}
        {mobile && <button onClick={onClose} className="ml-auto grid size-8 place-items-center rounded-sm hover:bg-subtle" aria-label="Close menu"><X className="size-5" /></button>}
      </div>
      <ul className="flex-1 space-y-0.5 overflow-y-auto p-3">
        {NAV.map((n, i) =>
          "group" in n ? (
            collapsed || !n.group ? <li key={i} className="my-2 h-px bg-[var(--border-subtle)]" aria-hidden /> :
              <li key={i} className="px-3 pt-4 pb-1 text-caption font-semibold text-fg-muted">{n.group}</li>
          ) : item(n.href, n.label, n.icon),
        )}
      </ul>
      <div className="space-y-0.5 border-t border-line p-3">
        <ul>{item("/settings", "Settings", Settings)}</ul>
        <Menu align="start" width={240} items={[
          ...((meta?.users ?? []).filter((u) => u.id !== user?.id).map((u) => ({ label: `Sign in as ${u.name} (${u.role})`, icon: <UserCog />, onSelect: () => switchUser(u.id) }))),
          { label: "", divider: true, onSelect: () => undefined },
          { label: "Theme: Light", icon: <Sun />, onSelect: () => setTheme("light"), shortcut: theme === "light" ? "✓" : "" },
          { label: "Theme: Night shift", icon: <Moon />, onSelect: () => setTheme("dark"), shortcut: theme === "dark" ? "✓" : "" },
          { label: "Theme: System", icon: <SunMoon />, onSelect: () => setTheme("system"), shortcut: theme === "system" ? "✓" : "" },
          { label: "", divider: true, onSelect: () => undefined },
          { label: "Keyboard shortcuts", icon: <Keyboard />, onSelect: onShortcuts, shortcut: "?" },
        ]} trigger={(p) => (
          <button {...p} className={clsx("flex h-11 w-full items-center gap-3 rounded-sm px-2 text-left hover:bg-subtle", collapsed && "justify-center px-0")} aria-label="User menu">
            <Avatar initials={user?.initials} size={28} />
            {!collapsed && (
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[14px] font-semibold">{user?.name ?? "…"}</span>
                <span className="block truncate text-caption text-fg-muted">{user ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : ""}</span>
              </span>
            )}
          </button>
        )} />
        {!mobile && (
          <button onClick={onToggle} className={clsx("hidden h-9 w-full items-center gap-3 rounded-sm px-3 text-[14px] text-fg-muted hover:bg-subtle lg:flex", collapsed && "justify-center px-0")}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            {collapsed ? <ChevronsRight className="size-5" /> : <><ChevronsLeft className="size-5" /><span>Collapse</span></>}
          </button>
        )}
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

function Notifications() {
  const { data } = useApi<{ recent: { id: string; title: string; status: string; updated_at: string }[] }>("/api/dashboard?period=quarter", { interval: 60000 });
  const wsHref = useWsHref();
  const items = data?.recent ?? [];
  return (
    <Popover align="end" width={340} label="Notifications" trigger={(p) => (
      <button {...p} className="relative grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-subtle" aria-label="Notifications">
        <Bell className="size-5" />
        {items.some((i) => i.status === "in_review") && <span className="absolute top-2 right-2 size-2 rounded-full bg-accent" />}
      </button>
    )}>
      {(close) => (
        <div className="p-2">
          <div className="px-2 py-1 text-h4 font-semibold">Recent activity</div>
          {items.length === 0 && <p className="px-2 py-3 text-fg-muted">Nothing new.</p>}
          {items.map((i) => (
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
