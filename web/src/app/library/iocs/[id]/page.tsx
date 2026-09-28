"use client";

import { RefreshCw } from "lucide-react";
import { useParams } from "next/navigation";
import { useState } from "react";
import { SeenIn } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { IocValue } from "@/components/research/ioc-value";
import { Badge, VerdictBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { ErrorState, Skeleton, useToast } from "@/components/ui/feedback";
import { Field, Select } from "@/components/ui/forms";
import { DefinitionList, Page, PageHeader, Panel } from "@/components/ui/layout";
import { patch, post } from "@/lib/api";
import { IOC_TYPE_LABEL, VERDICT } from "@/lib/constants";
import { defang, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { ResearchStatus, Severity, Verdict } from "@/lib/types";
import Link from "next/link";

interface ID {
  id: number; type: string; value: string; verdict: Verdict; reputation: Record<string, Record<string, unknown>>; reputation_summary: string;
  context: { research_id: string; context: string; role: string; sources: string[] }[];
  first_seen: string | null; last_seen: string | null; enriched_at: string | null; expires_at: string | null; research_count: number; source_count: number;
  seen_in: { id: string; title: string; severity: Severity; status: ResearchStatus; created_at: string }[];
}
const PROVIDER: Record<string, string> = { virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", greynoise: "GreyNoise", abusech: "abuse.ch", shodan: "Shodan", otx: "AlienVault OTX", urlscan: "urlscan.io" };

export default function IocDetail() {
  const { id } = useParams<{ id: string }>();
  const toast = useToast();
  const wsHref = useWsHref();
  const { data: i, error, reload, setData } = useApi<ID>(`/api/library/iocs/${id}`);
  const [busy, setBusy] = useState(false);
  if (error) return <Page><ErrorState error={error} onRetry={reload} /></Page>;
  if (!i) return <Page><div className="space-y-3 pt-8"><Skeleton className="h-8 w-1/3" /><Skeleton className="h-40 w-full" /></div></Page>;
  const enrich = async () => {
    setBusy(true);
    try { setData(await post<ID>(`/api/library/iocs/${i.id}/enrich`)); toast({ tone: "success", message: "Reputation refreshed" }); }
    catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "IoCs", href: "/library/iocs" }, { label: defang(i.value, i.type), mono: true }]}
        title={<span className="font-mono text-[22px] break-all">{defang(i.value, i.type)}</span>}
        description={<span className="flex items-center gap-2">{IOC_TYPE_LABEL[i.type] ?? i.type}<VerdictBadge verdict={i.verdict} /></span>}
        actions={<Button icon={<RefreshCw />} loading={busy} onClick={enrich}>Re-enrich</Button>} />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-6">
          <Panel title="Indicator"><IocValue type={i.type} value={i.value} verdict={i.verdict} sources={i.source_count} /></Panel>
          <Panel title="Reputation by OSINT source" bodyClassName="!p-0">
            {Object.keys(i.reputation ?? {}).length ? (
              <table className="tl-table tl-compact w-full">
                <thead><tr><th>Source</th><th>Signal</th><th>Detail</th></tr></thead>
                <tbody>{Object.entries(i.reputation).map(([k, v]) => (
                  <tr key={k}>
                    <td className="font-semibold">{PROVIDER[k] ?? k}</td>
                    <td>{v.error ? <span className="text-danger">{String(v.error)}</span> : String(v.summary ?? "—")}{v.flagged ? <Badge tone="danger" className="ml-2">Flagged</Badge> : null}</td>
                    <td className="max-w-[360px] truncate font-mono text-mono-sm text-fg-muted">{Object.entries(v).filter(([kk]) => !["summary", "flagged", "error"].includes(kk)).map(([kk, vv]) => `${kk}=${Array.isArray(vv) ? vv.join("|") : vv}`).join(" ")}</td>
                  </tr>
                ))}</tbody>
              </table>
            ) : <p className="p-4 text-fg-muted">Not enriched yet. Configure keys in <Link className="prose-link" href="/settings/osint">Settings → OSINT API keys</Link>, then re-enrich.</p>}
          </Panel>
          <Panel title="Context">
            <ul className="space-y-3">
              {i.context.map((c, k) => (
                <li key={k} className="text-[14px]">
                  <Link href={wsHref(`/research/${c.research_id}?tab=iocs`)} className="font-mono text-mono-sm text-accent-text hover:underline">{c.research_id}</Link>
                  {c.role && <Badge className="ml-2">{c.role}</Badge>}
                  {c.context && <p className="mt-1 italic text-fg-strong">“{c.context}”</p>}
                  {c.sources.length > 0 && <p className="text-caption text-fg-muted">Sources {c.sources.join(", ")}</p>}
                </li>
              ))}
            </ul>
          </Panel>
          <SeenIn items={i.seen_in} />
        </div>
        <aside className="space-y-4">
          <Panel title="Verdict">
            <Field label="Override verdict" htmlFor="v" help="Benign indicators are hidden from hunt queries by default.">
              <Select id="v" value={i.verdict} onChange={async (v) => { setData(await patch<ID>(`/api/library/iocs/${i.id}`, { verdict: v })); toast({ tone: "success", message: `Verdict set to ${VERDICT[v as Verdict].label}` }); }}
                options={Object.entries(VERDICT).map(([k, v]) => ({ value: k, label: v.label }))} />
            </Field>
          </Panel>
          <Panel title="Details">
            <DefinitionList items={[
              { label: "Type", value: IOC_TYPE_LABEL[i.type] ?? i.type },
              { label: "First seen", value: utc(i.first_seen) },
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
