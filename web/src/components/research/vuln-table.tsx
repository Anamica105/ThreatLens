"use client";

import clsx from "clsx";
import { ChevronRight, RefreshCw, ShieldAlert, TriangleAlert } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { post } from "@/lib/api";
import { SEVERITY } from "@/lib/constants";
import { relative, utc } from "@/lib/format";
import type { ResearchDetail, Severity } from "@/lib/types";
import { Badge, Chip, SeverityBadge } from "../ui/badges";
import { Button } from "../ui/button";
import { useToast } from "../ui/feedback";
import { Tooltip } from "../ui/overlay";
import { SourceChips, sourceIndex } from "./provenance";

type FeedState = "live" | "cache" | "stale" | "unavailable";

/** A research record vulnerability after CVE enrichment (NVD / CISA KEV / FIRST EPSS). Older records lack most fields. */
export interface EnrichedVuln {
  cve: string; cvss: number | null; description?: string; affected_products: string[]; fixed_versions: string[]; patch_kb: string[]; source_ids: string[];
  cvss_vector?: string | null; cvss_version?: string | null; cvss_severity?: string | null; cvss_source?: string | null;
  cwes?: string[]; nvd_status?: string | null; published?: string | null;
  affected_cpes?: ({ criteria: string; versionStartIncluding?: string; versionStartExcluding?: string; versionEndIncluding?: string; versionEndExcluding?: string } | string)[];
  kev_added: string | null; kev_due_date?: string | null; kev_required_action?: string | null; kev_ransomware?: "Known" | "Unknown" | null;
  epss: number | null; epss_percentile?: number | null; epss_date?: string | null;
  validation?: "verified" | "not_found" | "rejected" | "invalid_format" | "unchecked";
  enrichment?: { checked_at?: string | null; nvd?: FeedState; kev?: FeedState; epss?: FeedState };
}

/** POST /api/research/{id}/enrich-cves */
export interface EnrichResponse {
  changed: boolean; vulnerabilities: EnrichedVuln[]; version?: number;
  summary: { checked: number; enriched: number; not_found: string[]; invalid: string[]; rejected: string[]; sources: Record<string, string> };
}

const NOT_IN_NVD: Record<string, string> = {
  not_found: "NVD has no record of this CVE ID. Check the source for a typo.",
  rejected: "NVD lists this CVE ID as rejected.",
  invalid_format: "This is not a valid CVE ID.",
};
const FEED_NAME = { nvd: "NVD", kev: "CISA KEV", epss: "EPSS" } as const;
/** Floored so 0.99998 reads 99.9%, never a misleading 100%. */
const pct = (v: number) => `${Math.floor(v * 1000) / 10}%`;
const day = (v?: string | null) => (v ? utc(v, false) : "—");
const cpeText = (c: NonNullable<EnrichedVuln["affected_cpes"]>[number]) => {
  if (typeof c === "string") return c;
  const bounds = [
    c.versionStartIncluding && `≥ ${c.versionStartIncluding}`, c.versionStartExcluding && `> ${c.versionStartExcluding}`,
    c.versionEndIncluding && `≤ ${c.versionEndIncluding}`, c.versionEndExcluding && `< ${c.versionEndExcluding}`,
  ].filter(Boolean).join(", ");
  return bounds ? `${c.criteria} (${bounds})` : c.criteria;
};

function Cvss({ v }: { v: EnrichedVuln }) {
  if (v.cvss == null) return <span className="text-fg-muted">—</span>;
  const sev = (v.cvss_severity ?? "").toLowerCase();
  const tip = [v.cvss_vector, v.cvss_version && `CVSS v${v.cvss_version}`, v.cvss_source && `Scored by ${v.cvss_source}`].filter(Boolean).join(" · ");
  const body = (
    <span tabIndex={tip ? 0 : undefined} className="inline-flex items-center gap-2 rounded-sm focus-visible:outline-2 focus-visible:outline-[var(--accent)]">
      <span className="tabular font-semibold">{v.cvss.toFixed(1)}</span>
      {sev in SEVERITY && <SeverityBadge severity={sev as Severity} />}
    </span>
  );
  return tip ? <Tooltip content={<span className="break-all">{tip}</span>}>{body}</Tooltip> : body;
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption text-fg-muted">{label}</dt>
      <dd className="mt-0.5 min-w-0 text-body-sm break-words [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

const list = (xs?: string[] | null) => (xs?.length ? xs.join(", ") : "—");

/**
 * CVE table (spec §7 vulnerabilities): CVSS, EPSS, CISA KEV and NVD validation per CVE, with an expander for the
 * detail and a "Refresh CVE data" action. `onRefreshed` (e.g. the detail page's reload) is called after a refresh that
 * changed the record; the table also shows the refreshed values straight away.
 */
export function VulnTable({ d, canEdit, onRefreshed }: { d: ResearchDetail; canEdit: boolean; onRefreshed?: () => void | Promise<void> }) {
  const toast = useToast();
  const sources = useMemo(() => sourceIndex(d.record), [d.record]);
  const [fresh, setFresh] = useState<{ key: string; items: EnrichedVuln[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const key = `${d.id}|${d.version}|${d.updated_at}`;
  const vulns = (fresh && fresh.key === key ? fresh.items : (d.record.vulnerabilities ?? [])) as EnrichedVuln[];

  const checkedAt = vulns.map((v) => v.enrichment?.checked_at).filter((x): x is string => !!x).sort().pop() ?? null;
  const degraded = (["nvd", "kev", "epss"] as const).map((f) => {
    const states = vulns.map((v) => v.enrichment?.[f]).filter(Boolean) as FeedState[];
    return { f, unavailable: states.includes("unavailable"), stale: states.includes("stale") };
  }).filter((x) => x.unavailable || x.stale);

  const refresh = async () => {
    setBusy(true);
    try {
      const r = await post<EnrichResponse>(`/api/research/${d.id}/enrich-cves`);
      setFresh({ key, items: r.vulnerabilities });
      const bad = [...r.summary.not_found, ...r.summary.rejected, ...r.summary.invalid];
      toast({
        tone: bad.length ? "warning" : "success",
        message: r.changed ? `CVE data refreshed for ${r.summary.enriched} of ${r.summary.checked} CVEs${bad.length ? ` · not in NVD: ${bad.join(", ")}` : ""}` : "CVE data is already up to date",
      });
      if (r.changed) await onRefreshed?.();
    } catch (e) {
      toast({ tone: "danger", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const toggle = (cve: string) => setOpen((s) => { const n = new Set(s); if (n.has(cve)) n.delete(cve); else n.add(cve); return n; });

  if (!vulns.length) return null;
  return (
    <div className="min-w-0 space-y-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <p className="text-caption text-fg-muted">
          {checkedAt ? <>CVE data as of <span title={utc(checkedAt)}>{utc(checkedAt)}</span> ({relative(checkedAt)}) · NVD, CISA KEV, FIRST EPSS</> : "CVE data from the research sources; not yet checked against NVD, CISA KEV or EPSS."}
        </p>
        {canEdit && <Button size="sm" className="ml-auto" icon={<RefreshCw />} loading={busy} onClick={refresh}>Refresh CVE data</Button>}
      </div>
      {degraded.length > 0 && (
        <p className="flex items-start gap-1.5 text-body-sm" style={{ color: "var(--warning)" }}>
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          <span>
            {degraded.map((x) => `${FEED_NAME[x.f]} ${x.unavailable ? "unavailable" : "stale (cached)"}`).join(" · ")} at the last check;
            {" "}some values may come from the research sources or an older cache.{canEdit ? " Refresh to try again." : ""}
          </span>
        </p>
      )}
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="tl-table tl-compact w-full min-w-[640px]">
          <thead>
            <tr><th className="w-8"><span className="sr-only">Details</span></th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>CISA KEV</th></tr>
          </thead>
          <tbody>
            {vulns.map((v) => {
              const isOpen = open.has(v.cve);
              const notInNvd = v.validation && NOT_IN_NVD[v.validation];
              const detailId = `vuln-${v.cve}`;
              return (
                <Fragment key={v.cve}>
                  <tr className={clsx(isOpen && "bg-subtle")}>
                    <td className="align-top">
                      <button type="button" onClick={() => toggle(v.cve)} aria-expanded={isOpen} aria-controls={detailId} aria-label={`${isOpen ? "Hide" : "Show"} details for ${v.cve}`}
                        className="grid size-6 place-items-center rounded-sm text-fg-muted hover:bg-subtle">
                        <ChevronRight className={clsx("size-4 transition-transform", isOpen && "rotate-90")} />
                      </button>
                    </td>
                    <td className="align-top">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}`} target="_blank" rel="noopener noreferrer" className="font-mono text-mono-sm font-semibold text-accent-text hover:underline">{v.cve}</a>
                        {notInNvd && <Badge tone="danger" title={notInNvd}>Not in NVD</Badge>}
                        {v.validation === "unchecked" && <Badge tone="muted" title="Not yet checked against NVD">Unchecked</Badge>}
                      </div>
                      {v.description && <p className="mt-1 line-clamp-2 max-w-[520px] text-body-sm text-fg-muted">{v.description}</p>}
                    </td>
                    <td className="align-top whitespace-nowrap"><Cvss v={v} /></td>
                    <td className="align-top whitespace-nowrap">
                      {v.epss == null ? <span className="text-fg-muted">—</span> : (
                        <Tooltip content={`Probability of exploitation in the next 30 days${v.epss_date ? ` (EPSS ${day(v.epss_date)})` : ""}`}>
                          <span tabIndex={0} className="inline-block rounded-sm focus-visible:outline-2 focus-visible:outline-[var(--accent)]">
                            <span className="tabular font-semibold">{pct(v.epss)}</span>
                            {v.epss_percentile != null && <span className="block text-caption text-fg-muted">{Math.floor(v.epss_percentile * 1000) / 10}th percentile</span>}
                          </span>
                        </Tooltip>
                      )}
                    </td>
                    <td className="align-top">
                      {v.kev_added ? (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Badge tone="danger" title={`Added to CISA Known Exploited Vulnerabilities on ${day(v.kev_added)}`}>
                            <ShieldAlert className="mr-1 inline size-3.5 align-[-2px]" aria-hidden />KEV · {day(v.kev_added)}
                          </Badge>
                          {v.kev_ransomware === "Known" && <Badge tone="critical" title="CISA: known to be used in ransomware campaigns">Ransomware</Badge>}
                        </div>
                      ) : <span className="text-fg-muted">Not listed</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr id={detailId} className="bg-subtle">
                      <td />
                      <td colSpan={4} className="!pt-0">
                        <dl className="grid gap-x-6 gap-y-3 py-2 sm:grid-cols-2">
                          {v.description && <div className="sm:col-span-2"><Detail label="Description"><span className="whitespace-pre-line">{v.description}</span></Detail></div>}
                          <Detail label="Weakness (CWE)">{v.cwes?.length ? <span className="flex flex-wrap gap-1">{v.cwes.map((c) => <Chip key={c} mono href={/^CWE-\d+$/.test(c) ? `https://cwe.mitre.org/data/definitions/${c.slice(4)}.html` : undefined}>{c}</Chip>)}</span> : "—"}</Detail>
                          <Detail label="NVD">{v.nvd_status ?? (notInNvd ? "Not in NVD" : "—")}{v.published ? ` · published ${day(v.published)}` : ""}</Detail>
                          {v.kev_added && <>
                            <Detail label="KEV due date">{day(v.kev_due_date)}</Detail>
                            <Detail label="Known ransomware use">{v.kev_ransomware ?? "—"}</Detail>
                            {v.kev_required_action && <div className="sm:col-span-2"><Detail label="CISA required action">{v.kev_required_action}</Detail></div>}
                          </>}
                          <Detail label="Affected products">{list(v.affected_products)}</Detail>
                          <Detail label="Fixed versions">{list(v.fixed_versions)}</Detail>
                          <Detail label="Patches (KB)">{v.patch_kb?.length ? <span className="flex flex-wrap gap-1">{v.patch_kb.map((k) => <Chip key={k} mono>{k}</Chip>)}</span> : "—"}</Detail>
                          {!!v.affected_cpes?.length && (
                            <div className="sm:col-span-2">
                              <Detail label="Affected configurations (CPE)">
                                <ul className="space-y-0.5 font-mono text-mono-sm">{v.affected_cpes.slice(0, 8).map((c, i) => <li key={i}>{cpeText(c)}</li>)}</ul>
                                {v.affected_cpes.length > 8 && <span className="text-caption text-fg-muted">+{v.affected_cpes.length - 8} more</span>}
                              </Detail>
                            </div>
                          )}
                          <div className="sm:col-span-2"><Detail label="Sources"><SourceChips ids={v.source_ids ?? []} sources={sources} label="" empty="No source recorded" /></Detail></div>
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
