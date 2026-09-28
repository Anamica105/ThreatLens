"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { get } from "./api";

/** Minimal data hook: fetches on key change, keeps previous data while refreshing. */
export function useApi<T>(url: string | null, opts?: { interval?: number }) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(!!url);
  const seq = useRef(0);

  const load = useCallback(async () => {
    if (!url) return;
    const my = ++seq.current;
    setLoading(true);
    try {
      const d = await get<T>(url);
      if (my === seq.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (my === seq.current) setError(e as Error);
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!opts?.interval || !url) return;
    const t = setInterval(load, opts.interval);
    return () => clearInterval(t);
  }, [opts?.interval, url, load]);

  return { data, error, loading, reload: load, setData };
}

/** Show a skeleton only if loading takes longer than 200 ms, to avoid flashes. */
export function useDelayed(flag: boolean, ms = 200) {
  const [show, setShow] = useState(false);
  useEffect(() => {
    if (!flag) {
      setShow(false);
      return;
    }
    const t = setTimeout(() => setShow(true), ms);
    return () => clearTimeout(t);
  }, [flag, ms]);
  return show;
}

export function useLocalStorage<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(initial);
  useEffect(() => {
    try {
      const raw = localStorage.getItem(key);
      if (raw !== null) setValue(JSON.parse(raw));
    } catch {
      /* ignore */
    }
  }, [key]);
  const set = useCallback(
    (v: T) => {
      setValue(v);
      try {
        localStorage.setItem(key, JSON.stringify(v));
      } catch {
        /* ignore */
      }
    },
    [key],
  );
  return [value, set] as const;
}

export function useClickOutside(ref: React.RefObject<HTMLElement | null>, onOutside: () => void, active = true) {
  useEffect(() => {
    if (!active) return;
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onOutside();
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [ref, onOutside, active]);
}

export function useDebounced<T>(value: T, ms = 300) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}
