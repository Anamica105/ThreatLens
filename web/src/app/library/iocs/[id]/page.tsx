"use client";

import { RefreshCw, RotateCcw } from "lucide-react";
import { useParams } from "next/navigation";
import { useState } from "react";
import { SeenIn } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { IocValue } from "@/components/research/ioc-value";
import { SourceTrail } from "@/components/research/provenance";
import { AnyVerdictBadge, VERDICT_LABEL, type AnyVerdict, type IocOverride } from "@/components/research/detail/iocs-tab";
import { Badge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { ErrorState, Skeleton, useToast } from "@/components/ui/feedback";
import { Field, Select, Textarea } from "@/components/ui/forms";
import { DefinitionList, Page, PageHeader, Panel } from "@/components/ui/layout";
import { patch, post } from "@/lib/api";
import { IOC_TYPE_LABEL } from "@/lib/constants";
import { defang, relative, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { ProvenanceItem, ResearchStatus, Severity } from "@/lib/types";
import Link from "next/link";

interface ID {
  id: number; type: string; value: string; verdict: AnyVerdict; verdict_override: IocOverride | null; expired?: boolean; intel_first_seen?: string | null; reputation: Record<string, Record<string, unknown>>; reputation_summary: string;
  context: { research_id: string; context: string; role: string; sources: string[] }[];
  first_seen: string | null; last_seen: string | null; enriched_at: string | null; expires_at: string | null; research_count: number; source_count: number;
  seen_in: { id: string; title: string; severity: Severity; status: ResearchStatus; created_at: string }[];
  provenance?: ProvenanceItem[]; provenance_total?: number;
}
const PROVIDER: Record<string, string> = { virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", greynoise: "GreyNoise", abusech: "abuse.ch", shodan: "Shodan", otx: "AlienVault OTX", urlscan: "urlscan.io" };

export default function IocDetail() {
  const { id } = useParams<{ id: string }>();
  const toast = useToast();
  const wsHref = useWsHref();
  const { data: i, error, reload, setData } = useApi<ID>(`/api/library/iocs/${id}`);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  if (error) return <Page><ErrorState error={error} onRetry={reload} /></Page>;
  if (!i) return <Page><div className="space-y-3 pt-8"><Skeleton className="h-8 w-1/3" /><Skeleton className="h-40 w-full" /></div></Page>;
  const enrich = async () => {
    setBusy(true);
    try { setData(await post<ID>(`/api/library/iocs/${i.id}/enrich`)); toast({ tone: "success", message: "Reputation refreshed" }); }
    catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };
  const setVerdict = async (body: { verdict?: string; clear_override?: boolean; note?: string }, message: string) => {
    setBusy(true);
    try { setData(await patch<ID>(`/api/library/iocs/${i.id}`, body)); setNote(""); toast({ tone: "success", message }); }
    catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };
  const ov = i.verdict_override;
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "IoCs", href: "/library/iocs" }, { label: defang(i.value, i.type), mono: true }]}
        title={<span className="font-mono text-[22px] break-all">{defang(i.value, i.type)}</span>}
        description={<span className="flex items-center gap-2">{IOC_TYPE_LABEL[i.type] ?? i.type}<AnyVerdictBadge verdict={i.verdict} />{ov && <Badge>Analyst override</Badge>}</span>}
        actions={<Button icon={<RefreshCw />} loading={busy} onClick={enrich}>Re-enrich</Button>} />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-6">
          <Panel title="Indicator"><IocValue type={i.type} value={i.value} verdict={i.verdict === "false_positive" ? "benign" : i.verdict} sources={i.source_count} /></Panel>
          <Panel title="Reputation by OSINT source" bodyClassName="!p-0">
            {Object.keys(i.reputation ?? {}).length ? (
              <div className="overflow-x-auto"><table className="tl-table tl-compact w-full">
                <thead><tr><th>Source</th><th>Signal</th><th>Detail</th></tr></thead>
                <tbody>{Object.entries(i.reputation).map(([k, v]) => (
                  <tr key={k}>
                    <td className="font-semibold">{PROVIDER[k] ?? k}</td>
                    <td>{v.error ? <span className="text-danger">{String(v.error)}</span> : String(v.summary ?? "—")}{v.flagged ? <Badge tone="danger" className="ml-2">Flagged</Badge> : null}</td>
                    <td className="max-w-[360px] truncate font-mono text-mono-sm text-fg-muted">{Object.entries(v).filter(([kk]) => !["summary", "flagged", "error"].includes(kk)).map(([kk, vv]) => `${kk}=${Array.isArray(vv) ? vv.join("|") : vv}`).join(" ")}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            ) : <p className="p-4 text-fg-muted">Not enriched yet. Configure keys in <Link className="prose-link" href="/settings/osint">Settings → OSINT API keys</Link>, then re-enrich.</p>}
          </Panel>
          <Panel title="Context">
            <ul className="space-y-3">
              {i.context.map((c, k) => (
                <li key={k} className="min-w-0 text-[14px] break-words">
                  <Link href={wsHref(`/research/${c.research_id}?tab=iocs`)} className="font-mono text-mono-sm text-accent-text hover:underline">{c.research_id}</Link>
                  {c.role && <Badge className="ml-2">{c.role}</Badge>}
                  {c.context && <p className="mt-1 italic text-fg-strong">“{c.context}”</p>}
                  {c.sources.length > 0 && <p className="text-caption text-fg-muted">Sources {c.sources.join(", ")}</p>}
                </li>
              ))}
            </ul>
          </Panel>
          <SourceTrail items={i.provenance} total={i.provenance_total} wsHref={wsHref} />
          <SeenIn items={i.seen_in} />
        </div>
        <aside className="min-w-0 space-y-4">
          <Panel title="Verdict">
            <div className="space-y-3">
              {ov ? (
                <div className="rounded-md border border-line bg-subtle p-3 text-body-sm">
                  <div className="flex flex-wrap items-center gap-2"><span className="font-semibold">Analyst override</span><AnyVerdictBadge verdict={ov.verdict} /></div>
                  <p className="mt-1 text-fg-muted" title={ov.at ? utc(ov.at) : undefined}>{ov.by_name ?? ov.by ?? "Analyst"}{ov.at ? ` · ${relative(ov.at)}` : ""}{ov.research_id ? ` · from ${ov.research_id}` : ""}</p>
                  {ov.note && <p className="mt-1 italic text-fg-strong break-words">“{ov.note}”</p>}
                  <p className="mt-1 text-caption text-fg-muted">Later runs and enrichment keep this verdict. Benign and false positive indicators are left out of retro-hunts.</p>
                  <Button className="mt-2" size="sm" icon={<RotateCcw />} loading={busy} onClick={() => setVerdict({ clear_override: true }, "Override cleared; the pipeline verdict applies again")}>Clear override</Button>
                </div>
              ) : <p className="text-body-sm text-fg-muted">No analyst override: the verdict comes from the pipeline and OSINT enrichment.</p>}
              <Field label={ov ? "Change override" : "Override verdict"} htmlFor="v" help="Benign and false positive indicators are hidden from hunt queries by default.">
                <Select id="v" value={i.verdict} disabled={busy} onChange={(v) => setVerdict({ verdict: v, ...(note.trim() ? { note: note.trim() } : {}) }, `Verdict set to ${VERDICT_LABEL[v as AnyVerdict] ?? v}`)}
                  options={(Object.keys(VERDICT_LABEL) as AnyVerdict[]).map((k) => ({ value: k, label: VERDICT_LABEL[k] }))} />
              </Field>
              <Field label="Note" optional htmlFor="ov-note" help="Saved with the next verdict you pick.">
                <Textarea id="ov-note" rows={2} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
              </Field>
            </div>
          </Panel>
          <Panel title="Details">
            <DefinitionList items={[
              { label: "Type", value: IOC_TYPE_LABEL[i.type] ?? i.type },
              { label: "First seen", value: utc(i.first_seen) },
              { label: "Intel first seen", value: i.intel_first_seen ? utc(i.intel_first_seen, false) : "Unknown" },
              { label: i.expired ? "Expired" : "Expires", value: i.expires_at ? utc(i.expires_at, false) : "Never" },
              { label: "Last seen", value: utc(i.last_seen) },
              { label: "Enriched", value: i.enriched_at ? utc(i.enriched_at) : "Never" },
              { label: "Sources", value: `×${i.source_count}` },
              { label: "Research", value: i.research_count },
            ]} />
          </Panel>
        </aside>
      </div>
    </Page>
  );
}
