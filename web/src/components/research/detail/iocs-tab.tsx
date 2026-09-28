"use client";

import { Copy, Download, Fingerprint, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { download } from "@/lib/api";
import { IOC_TYPE_LABEL, VERDICT } from "@/lib/constants";
import { defang, refang } from "@/lib/format";
import { copyText } from "@/lib/hooks";
import type { IocRow, Verdict } from "@/lib/types";
import { FilterButton } from "../../filters";
import { Badge, VerdictBadge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { EmptyState, useToast } from "../../ui/feedback";
import { Checkbox, Input } from "../../ui/forms";
import { Drawer, Menu } from "../../ui/overlay";
import { IocValue } from "../ioc-value";
import type { DetailProps } from "./common";

export function IocsTab({ d, ws }: DetailProps) {
  const rec = d.record;
  const toast = useToast();
  const sources = useMemo(() => Object.fromEntries(rec.sources.map((s) => [s.id, s])), [rec.sources]);
  const [q, setQ] = useState("");
  const [types, setTypes] = useState<string[]>([]);
  const [verdicts, setVerdicts] = useState<string[]>(["malicious", "suspicious", "unknown", "expired"]);
  const [sel, setSel] = useState<string[]>([]);
  const [open, setOpen] = useState<number | null>(null);

  const rows = rec.iocs.filter((i) => (!types.length || types.includes(i.type)) && (!verdicts.length || verdicts.includes(i.verdict))
    && (!q || refang(i.value).toLowerCase().includes(refang(q).toLowerCase())));
  const key = (i: IocRow) => i.type + "|" + i.value;
  const chosen = rows.filter((i) => sel.includes(key(i)));

  const bulkCopy = async (raw: boolean, withType: boolean) => {
    const list = (chosen.length ? chosen : rows);
    await copyText(list.map((i) => `${withType ? i.type + "\t" : ""}${raw ? refang(i.value) : defang(i.value, i.type)}`).join("\n"));
    toast({ tone: "success", message: `Copied ${list.length} ${raw ? "live" : "defanged"} indicator${list.length === 1 ? "" : "s"}` });
  };

  if (!rec.iocs.length)
    return <EmptyState icon={<Fingerprint />} title="No indicators in these sources" body="This threat is described by behaviour only. See the IoA queries." action={<a href="?tab=hunts" className="prose-link">Open Hunts</a>} />;

  const cur = open !== null ? rows[open] : null;
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input inputSize="md" className="w-64" prefixIcon={<Search />} placeholder="Filter indicators" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter indicators" />
        <FilterButton label="Type" values={types} onChange={setTypes} options={Array.from(new Set(rec.iocs.map((i) => i.type))).map((t) => ({ value: t, label: IOC_TYPE_LABEL[t] ?? t, count: rec.iocs.filter((i) => i.type === t).length }))} />
        <FilterButton label="Verdict" values={verdicts} onChange={setVerdicts} options={(Object.keys(VERDICT) as Verdict[]).map((v) => ({ value: v, label: VERDICT[v].label, count: rec.iocs.filter((i) => i.verdict === v).length }))} />
        <span className="text-caption text-fg-muted">Benign and false positives are hidden by default.</span>
        <div className="ml-auto flex gap-2">
          <Menu width={240} items={[
            { label: "Copy defanged, values only", icon: <Copy />, onSelect: () => bulkCopy(false, false) },
            { label: "Copy defanged, with type", icon: <Copy />, onSelect: () => bulkCopy(false, true) },
            { label: "Copy raw (refanged)", icon: <Copy />, onSelect: () => bulkCopy(true, false) },
          ]} trigger={(p) => <Button {...p} size="md" icon={<Copy />}>Copy {chosen.length ? chosen.length : "all"}</Button>} />
          <Button icon={<Download />} onClick={() => download(`/api/research/${d.id}/export/iocs_csv${ws !== "all" ? `?ws=${ws}` : ""}`)}>CSV</Button>
        </div>
      </div>
      <div className="overflow-x-auto rounded-md border border-line bg-surface">
        <table className="tl-table tl-compact w-full">
          <thead><tr>
            <th className="w-8"><Checkbox checked={rows.length > 0 && chosen.length === rows.length} indeterminate={chosen.length > 0 && chosen.length < rows.length} onChange={(v) => setSel(v ? rows.map(key) : [])} label={<span className="sr-only">Select all</span>} /></th>
            <th>Indicator</th><th>Type</th><th>Verdict</th><th>Reputation</th><th>Role / context</th><th className="num">Sources</th>
          </tr></thead>
          <tbody>
            {rows.map((i, idx) => (
              <tr key={key(i)} aria-selected={sel.includes(key(i))} style={{ opacity: i.verdict === "expired" ? 0.7 : 1 }}>
                <td><Checkbox checked={sel.includes(key(i))} onChange={(v) => setSel(v ? [...sel, key(i)] : sel.filter((x) => x !== key(i)))} label={<span className="sr-only">Select</span>} /></td>
                <td className="max-w-[420px]"><IocValue type={i.type} value={i.value} compact onOpen={() => setOpen(idx)} /></td>
                <td>{IOC_TYPE_LABEL[i.type] ?? i.type}</td>
                <td><VerdictBadge verdict={i.verdict} /></td>
                <td className="max-w-[220px] truncate text-fg-muted">{i.reputation_summary || "Not enriched"}</td>
                <td className="max-w-[320px] truncate" title={i.context}>{i.role || i.context || "—"}</td>
                <td className="num"><span className="font-mono">×{i.source_ids.length}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="p-6 text-center text-fg-muted">No indicators match these filters.</p>}
      </div>
      <Drawer open={!!cur} onClose={() => setOpen(null)} title={cur ? <span className="font-mono text-mono break-all">{defang(cur.value, cur.type)}</span> : ""}
        subtitle={cur ? IOC_TYPE_LABEL[cur.type] : ""} onPrev={open ? () => setOpen(open - 1) : undefined} onNext={open !== null && open < rows.length - 1 ? () => setOpen(open + 1) : undefined}>
        {cur && (
          <div className="space-y-5">
            <IocValue type={cur.type} value={cur.value} verdict={cur.verdict} sources={cur.source_ids.length} publishers={cur.source_ids.map((s) => sources[s]?.publisher ?? s)} />
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Reputation</h3>
              {Object.keys(cur.reputation ?? {}).length ? (
                <table className="tl-table tl-compact w-full"><tbody>
                  {Object.entries(cur.reputation).map(([k, v]) => <tr key={k}><td className="font-semibold">{k}</td><td>{String(v.summary ?? JSON.stringify(v))}</td></tr>)}
                </tbody></table>
              ) : <p className="text-fg-muted">Not enriched. Add OSINT keys in Settings, then enrich from the IoC library.</p>}
            </div>
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Context</h3>
              {cur.role && <p className="mb-2"><Badge>{cur.role}</Badge></p>}
              <ul className="space-y-2">{(cur.contexts?.length ? cur.contexts : [cur.context]).filter(Boolean).map((c, i) => <li key={i} className="text-[14px] italic text-fg-strong">“{c}”</li>)}</ul>
            </div>
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Mentioned by</h3>
              <ul className="space-y-1">{cur.source_ids.map((s) => <li key={s} className="text-[14px]"><span className="font-mono text-mono-sm text-fg-muted">{s}</span> {sources[s]?.publisher ?? s}</li>)}</ul>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
