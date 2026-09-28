"use client";

import { ChevronDown } from "lucide-react";
import { useCallback, useState } from "react";
import { QUERY_STATUS, QUERY_STATUS_ORDER } from "@/lib/constants";
import type { Query } from "@/lib/types";
import { QueryStatusPill } from "../../ui/badges";
import { Menu } from "../../ui/overlay";

/** Fields the API adds to a query when `?ws=<workspace>` is given (server-side field mapping). */
export interface MappedFields { mapped_body?: string; mapped_lint?: string[]; mapping_applied?: boolean }
export type MappedQuery = Query & MappedFields;

/** GET /api/research/{id}/queries?ws= */
export interface ResearchQueriesResponse {
  research_id: string; workspace_id: string | null; field_mappings: Record<string, Record<string, string>> | null;
  statuses: string[]; total: number; items: MappedQuery[];
}

const NEEDS_CLEAN_LINT = new Set(["syntax_checked", "reviewed", "lab_tested", "deployed"]);

/**
 * Statuses a query may move to from `current` (mirrors api detection.check_status_change): "reference" only for vendor
 * queries, vendor queries are never generated / syntax-checked, and a query with lint findings cannot move to
 * syntax-checked or later. Demotions are allowed.
 */
export function allowedStatuses(current: string, origin: string | undefined, lint: string[] | undefined, statuses: string[] = QUERY_STATUS_ORDER) {
  const vendor = origin === "reference";
  return statuses.filter((s) => {
    if (s === current) return false;
    if (s === "reference" && !vendor) return false;
    if (vendor && (s === "generated" || s === "syntax_checked")) return false;
    if (!vendor && (lint?.length ?? 0) > 0 && NEEDS_CLEAN_LINT.has(s)) return false;
    return true;
  });
}

export const statusLabel = (s: string) => QUERY_STATUS[s]?.label ?? s;

/**
 * Optimistic status: `status` shows the pending value while `change` runs, then falls back to the server value.
 * `change` must reject on error (the caller shows the API `detail`); the override is cleared either way, so a failed
 * PATCH rolls the UI back and a successful one shows whatever the reloaded record says.
 */
export function useOptimisticStatus(serverStatus: string, commit: (status: string) => Promise<unknown>) {
  const [pending, setPending] = useState<string | null>(null);
  const change = useCallback(async (s: string) => {
    setPending(s);
    try { await commit(s); } catch { /* caller reports */ } finally { setPending(null); }
  }, [commit]);
  return { status: pending ?? serverStatus, busy: pending !== null, change };
}

/** Status pill that opens a menu of the valid next states. Read-only pill when `onChange` is absent. */
export function StatusPicker({ status, origin, lint, onChange, busy, statuses }:
  { status: string; origin?: string; lint?: string[]; onChange?: (s: string) => void; busy?: boolean; statuses?: string[] }) {
  if (!onChange) return <QueryStatusPill status={status} />;
  const next = allowedStatuses(status, origin, lint, statuses);
  const blocked = origin !== "reference" && (lint?.length ?? 0) > 0;
  return (
    <Menu width={230} items={[
      ...next.map((s) => ({ label: `Mark ${statusLabel(s)}`, onSelect: () => onChange(s) })),
      ...(blocked ? [{ divider: true, label: "", onSelect: () => undefined }, { label: "Fix lint to advance", disabled: true, onSelect: () => undefined }] : []),
    ]} trigger={(p) => (
      <button {...p} disabled={busy} aria-label={`Status: ${statusLabel(status)}. Change status`}
        className="inline-flex items-center gap-0.5 rounded-full focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] disabled:opacity-60">
        <QueryStatusPill status={status} />
        <ChevronDown className="size-3.5 text-fg-muted" aria-hidden />
      </button>
    )} />
  );
}
