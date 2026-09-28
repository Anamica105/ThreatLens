"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { get, getUserId, patch, setUserId } from "@/lib/api";
import type { Meta, User, Workspace } from "@/lib/types";

type Theme = "light" | "dark" | "system";

interface AppCtx {
  meta: Meta | null;
  user: User | null;
  workspaces: Workspace[];
  ws: string; // "all" or workspace id
  activeWorkspace: Workspace | null;
  setWs: (id: string) => void;
  switchUser: (id: string) => void;
  theme: Theme;
  setTheme: (t: Theme) => void;
  reloadWorkspaces: () => Promise<void>;
  platformName: (id: string, short?: boolean) => string;
  wsName: (id: string) => string;
}

const Ctx = createContext<AppCtx | null>(null);

export function useApp() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useApp outside provider");
  return c;
}

const WS_KEY = "tl.ws";
const THEME_KEY = "tl.theme";

function applyTheme(t: Theme) {
  const dark = t === "dark" || (t === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [meta, setMeta] = useState<Meta | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [theme, setThemeState] = useState<Theme>("light");
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const [storedWs, setStoredWs] = useState<string>("all");
  const urlWs = params.get("ws");
  const ws = urlWs || storedWs;

  const reloadWorkspaces = useCallback(async () => {
    setWorkspaces(await get<Workspace[]>("/api/workspaces"));
  }, []);

  useEffect(() => {
    try {
      setStoredWs(localStorage.getItem(WS_KEY) || "all");
      const t = (localStorage.getItem(THEME_KEY) as Theme) || "light";
      setThemeState(t);
      applyTheme(t);
    } catch {
      /* ignore */
    }
    get<Meta>("/api/meta").then(setMeta).catch(() => setMeta(null));
    get<User>("/api/me").then((u) => {
      setUser(u);
      if (!getUserId()) setUserId(u.id);
    }).catch(() => undefined);
    reloadWorkspaces().catch(() => undefined);
  }, [reloadWorkspaces]);

  useEffect(() => {
    if (theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const h = () => applyTheme("system");
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [theme]);

  // Keep ?ws= in the URL so links shared between hunters open in the same context.
  useEffect(() => {
    if (!urlWs && storedWs && storedWs !== "all") {
      const p = new URLSearchParams(params.toString());
      p.set("ws", storedWs);
      router.replace(`${pathname}?${p.toString()}`, { scroll: false });
    }
  }, [urlWs, storedWs, pathname, params, router]);

  const setWs = useCallback(
    (id: string) => {
      setStoredWs(id);
      try {
        localStorage.setItem(WS_KEY, id);
      } catch {
        /* ignore */
      }
      patch("/api/me", { preferences: { workspace: id } }).catch(() => undefined);
      const p = new URLSearchParams(params.toString());
      if (id === "all") p.delete("ws");
      else p.set("ws", id);
      const s = p.toString();
      router.replace(`${pathname}${s ? `?${s}` : ""}`, { scroll: false });
    },
    [params, pathname, router],
  );

  const switchUser = useCallback((id: string) => {
    setUserId(id);
    window.location.reload();
  }, []);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    applyTheme(t);
    try {
      localStorage.setItem(THEME_KEY, t);
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo<AppCtx>(() => {
    const activeWorkspace = workspaces.find((w) => w.id === ws) ?? null;
    return {
      meta, user, workspaces, ws: activeWorkspace ? ws : "all", activeWorkspace, setWs, switchUser, theme, setTheme, reloadWorkspaces,
      platformName: (id, short) => {
        const p = meta?.platforms.find((x) => x.id === id);
        return p ? (short ? p.short : p.name) : id;
      },
      wsName: (id) => workspaces.find((w) => w.id === id)?.name ?? id,
    };
  }, [meta, user, workspaces, ws, setWs, switchUser, theme, setTheme, reloadWorkspaces]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Append the active workspace to internal links. */
export function useWsHref() {
  const { ws } = useApp();
  return useCallback((href: string) => {
    if (ws === "all") return href;
    return href + (href.includes("?") ? "&" : "?") + `ws=${ws}`;
  }, [ws]);
}
