"use client";

import { Ban, CircleSlash, Copy, Download, EyeOff, Fingerprint, MoreHorizontal, RotateCcw, Search, ShieldCheck, ShieldX } from "lucide-react";
import { useMemo, useState } from "react";
import { download, patch } from "@/lib/api";
import { IOC_TYPE_LABEL, VERDICT } from "@/lib/constants";
import { defang, refang, relative, utc } from "@/lib/format";
import { copyText } from "@/lib/hooks";
import type { IocRow, Verdict } from "@/lib/types";
import { FilterButton } from "../../filters";
import { Badge, VerdictBadge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { EmptyState, useToast } from "../../ui/feedback";
import { Checkbox, Field, Input, Textarea } from "../../ui/forms";
import { Dialog, Drawer, Menu, Tooltip } from "../../ui/overlay";
import { IocValue } from "../ioc-value";
import { SourceChips } from "../provenance";
import type { DetailProps } from "./common";

/* ------------------------------------------------------------------ types (API: PATCH /api/research/{id}/iocs) */

/** Verdicts including the analyst-only "false_positive" (lib/types Verdict predates it). */
export type AnyVerdict = Verdict | "false_positive";
export type ReviewVerdict = "malicious" | "suspicious" | "benign" | "false_positive";

export interface IocAnalyst { verdict?: ReviewVerdict; excluded?: boolean; note?: string; by?: string; by_name?: string; at?: string }
export interface IocOverride { verdict: AnyVerdict; by?: string | null; by_name?: string; at?: string; note?: string; research_id?: string }

/** A record indicator as returned after IoC review (extra fields are absent on records never reviewed). */
export interface ReviewedIoc extends Omit<IocRow, "verdict"> {
  verdict: AnyVerdict;
  pipeline_verdict?: AnyVerdict;
  verdict_source?: "pipeline" | "analyst" | "library";
  excluded?: boolean;
  hidden_from_hunts?: boolean;
  analyst?: IocAnalyst;
  library_override?: IocOverride;
  intel_first_seen?: string | null;
  expires_at?: string | null;
  known_good?: string;
}

interface IocDecision { type: string; value: string; verdict?: ReviewVerdict; excluded?: boolean; note?: string; restore?: boolean }
export interface IocReviewResponse {
  version: number; changes: { group: string; before: number; after: number }[]; hidden_count: number; updated: number; propagated: number;
}

export const VERDICT_LABEL: Record<AnyVerdict, string> = { ...Object.fromEntries(Object.entries(VERDICT).map(([k, v]) => [k, v.label])) as Record<Verdict, string>, false_positive: "False positive" };

/** VerdictBadge that also knows "false_positive" (shown with the benign styling plus a strike icon). */
export function AnyVerdictBadge({ verdict }: { verdict: AnyVerdict }) {
  if (verdict !== "false_positive") return <VerdictBadge verdict={verdict} />;
  return (
    <span className="inline-flex h-5 shrink-0 items-center gap-1 rounded-sm px-1.5 text-[12px] font-semibold leading-none whitespace-nowrap [&_svg]:size-3.5"
      style={{ background: "var(--neutral-chip-bg)", color: "var(--text-secondary)" }}>
      <CircleSlash />False positive
    </span>
  );
}

const HIDDEN = new Set<AnyVerdict>(["benign", "false_positive"]);

/** hidden_from_hunts as the API computes it, for records written before the field existed. */
export function isHidden(i: ReviewedIoc, includeExpired: boolean) {
  if (typeof i.hidden_from_hunts === "boolean") return i.hidden_from_hunts;
  return !!i.excluded || HIDDEN.has(i.verdict) || (i.verdict === "expired" && !includeExpired);
}

export function changesText(changes: IocReviewResponse["changes"]) {
  return changes.map((c) => `${c.group} ${c.before}→${c.after}`).join(", ");
}

/* ------------------------------------------------------------------ tab */

type Pending = { items: ReviewedIoc[]; verdict: ReviewVerdict };
const ACTION_LABEL: Record<ReviewVerdict, string> = { false_positive: "Mark false positive", benign: "Mark benign", suspicious: "Mark suspicious", malicious: "Mark malicious" };

export function IocsTab({ d, ws, reload, canEdit }: DetailProps) {
  const rec = d.record;
  const iocs = rec.iocs as unknown as ReviewedIoc[];
  const includeExpired = !!(rec as unknown as { ioc_review?: { include_expired?: boolean } }).ioc_review?.include_expired;
  const toast = useToast();
  const sources = useMemo(() => Object.fromEntries(rec.sources.map((s) => [s.id, s])), [rec.sources]);
  const [q, setQ] = useState("");
  const [types, setTypes] = useState<string[]>([]);
  const [verdicts, setVerdicts] = useState<string[]>(["malicious", "suspicious", "unknown", "expired"]);
  const [hiddenOnly, setHiddenOnly] = useState(false);
  const [sel, setSel] = useState<string[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [note, setNote] = useState("");
  const [propagate, setPropagate] = useState(false);
  const [busy, setBusy] = useState(false);

  const hiddenCount = iocs.filter((i) => isHidden(i, includeExpired)).length;
  const rows = iocs.filter((i) => (!types.length || types.includes(i.type))
    && (hiddenOnly ? isHidden(i, includeExpired) : (!verdicts.length || verdicts.includes(i.verdict)))
    && (!q || refang(i.value).toLowerCase().includes(refang(q).toLowerCase())));
  const key = (i: ReviewedIoc) => i.type + "|" + i.value;
  const chosen = rows.filter((i) => sel.includes(key(i)));

  const bulkCopy = async (raw: boolean, withType: boolean) => {
    const list = (chosen.length ? chosen : rows);
    await copyText(list.map((i) => `${withType ? i.type + "\t" : ""}${raw ? refang(i.value) : defang(i.value, i.type)}`).join("\n"));
    toast({ tone: "success", message: `Copied ${list.length} ${raw ? "live" : "defanged"} indicator${list.length === 1 ? "" : "s"}` });
  };

  const send = async (items: IocDecision[], opts: { propagate?: boolean; include_expired?: boolean } = {}, done?: string) => {
    setBusy(true);
    try {
      const res = await patch<IocReviewResponse>(`/api/research/${d.id}/iocs`, { items, ...opts });
      await reload();
      setSel([]);
      const regen = res.changes.length ? `Retro-hunt queries regenerated: ${changesText(res.changes)}` : "Retro-hunt queries unchanged";
      toast({ tone: "success", message: `${done ?? `${items.length} indicator${items.length === 1 ? "" : "s"} updated`}${res.propagated ? ` (${res.propagated} in the IoC library)` : ""}. ${regen}.` });
      return true;
    } catch (e) {
      toast({ tone: "danger", message: (e as Error).message });
      return false;
    } finally { setBusy(false); }
  };
  const ask = (items: ReviewedIoc[], verdict: ReviewVerdict) => {
    setNote(items.length === 1 ? items[0].analyst?.note ?? "" : "");
    setPropagate(false);
    setPending({ items, verdict });
  };
  const confirm = async () => {
    if (!pending) return;
    const ok = await send(pending.items.map((i) => ({ type: i.type, value: i.value, verdict: pending.verdict, ...(note.trim() ? { note: note.trim() } : {}) })),
      { propagate }, `${pending.items.length} indicator${pending.items.length === 1 ? "" : "s"} marked ${VERDICT_LABEL[pending.verdict].toLowerCase()}`);
    if (ok) setPending(null);
  };
  const exclude = (items: ReviewedIoc[], excluded: boolean) =>
    send(items.map((i) => ({ type: i.type, value: i.value, excluded })), {}, `${items.length} indicator${items.length === 1 ? "" : "s"} ${excluded ? "excluded from" : "included in"} hunts`);
  const restore = (items: ReviewedIoc[]) =>
    send(items.map((i) => ({ type: i.type, value: i.value, restore: true })), {}, `${items.length} indicator${items.length === 1 ? "" : "s"} restored`);

  if (!iocs.length)
    return <EmptyState icon={<Fingerprint />} title="No indicators in these sources" body="This threat is described by behaviour only. See the IoA queries." action={<a href="?tab=hunts" className="prose-link">Open Hunts</a>} />;

  const verdictKeys = [...(Object.keys(VERDICT) as Verdict[]), "false_positive"] as AnyVerdict[];
  const cur = open !== null ? rows[open] : null;
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input inputSize="md" className="w-full sm:w-64" prefixIcon={<Search />} placeholder="Filter indicators" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter indicators" />
        <FilterButton label="Type" values={types} onChange={setTypes} options={Array.from(new Set(iocs.map((i) => i.type))).map((t) => ({ value: t, label: IOC_TYPE_LABEL[t] ?? t, count: iocs.filter((i) => i.type === t).length }))} />
        {!hiddenOnly && <FilterButton label="Verdict" values={verdicts} onChange={setVerdicts} options={verdictKeys.map((v) => ({ value: v, label: VERDICT_LABEL[v], count: iocs.filter((i) => i.verdict === v).length }))} />}
        <button type="button" aria-pressed={hiddenOnly} onClick={() => { setHiddenOnly(!hiddenOnly); setSel([]); }}
          className={`inline-flex h-9 items-center gap-1.5 rounded-sm border px-3 text-[14px] font-medium [&_svg]:size-4 ${hiddenOnly ? "border-[var(--accent)] bg-accent-soft text-accent-text" : "border-line-strong bg-surface text-fg hover:bg-subtle"}`}>
          <EyeOff />Hidden from hunts ({hiddenCount})
        </button>
        {!hiddenOnly && <span className="text-caption text-fg-muted">Benign and false positives are hidden by default.</span>}
        <div className="ml-auto flex gap-2">
          <Menu width={240} items={[
            { label: "Copy defanged, values only", icon: <Copy />, onSelect: () => bulkCopy(false, false) },
            { label: "Copy defanged, with type", icon: <Copy />, onSelect: () => bulkCopy(false, true) },
            { label: "Copy raw (refanged)", icon: <Copy />, onSelect: () => bulkCopy(true, false) },
          ]} trigger={(p) => <Button {...p} size="md" icon={<Copy />}>Copy {chosen.length ? chosen.length : "all"}</Button>} />
          <Button icon={<Download />} onClick={() => download(`/api/research/${d.id}/export/iocs_csv${ws !== "all" ? `?ws=${ws}` : ""}`)}>CSV</Button>
        </div>
      </div>

      {canEdit && chosen.length > 0 && (
        <div role="toolbar" aria-label="Bulk indicator actions" className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-line bg-subtle px-3 py-2">
          <span className="mr-1 text-body-sm font-semibold">{chosen.length} selected</span>
          <Button size="sm" icon={<ShieldX />} disabled={busy} onClick={() => ask(chosen, "false_positive")}>Mark false positive</Button>
          <Button size="sm" icon={<ShieldCheck />} disabled={busy} onClick={() => ask(chosen, "benign")}>Mark benign</Button>
          <Button size="sm" icon={<Ban />} disabled={busy} onClick={() => exclude(chosen, true)}>Exclude from hunts</Button>
          <Button size="sm" icon={<RotateCcw />} disabled={busy || !chosen.some((i) => i.analyst)} disabledReason="None of these has an analyst decision" onClick={() => restore(chosen)}>Restore</Button>
          <Button size="sm" variant="tertiary" onClick={() => setSel([])}>Clear selection</Button>
        </div>
      )}

      <div className="overflow-x-auto rounded-md border border-line bg-surface">
        <table className="tl-table tl-compact w-full">
          <thead><tr>
            <th className="w-8"><Checkbox checked={rows.length > 0 && chosen.length === rows.length} indeterminate={chosen.length > 0 && chosen.length < rows.length} onChange={(v) => setSel(v ? rows.map(key) : [])} label={<span className="sr-only">Select all</span>} /></th>
            <th>Indicator</th><th>Type</th><th>Verdict</th><th>Reputation</th><th>Role and context</th><th>Sources</th>{canEdit && <th className="w-10"><span className="sr-only">Actions</span></th>}
          </tr></thead>
          <tbody>
            {rows.map((i, idx) => {
              const hidden = isHidden(i, includeExpired);
              return (
                <tr key={key(i)} aria-selected={sel.includes(key(i))} style={{ opacity: i.verdict === "expired" || hidden ? 0.72 : 1 }}>
                  <td><Checkbox checked={sel.includes(key(i))} onChange={(v) => setSel(v ? [...sel, key(i)] : sel.filter((x) => x !== key(i)))} label={<span className="sr-only">Select</span>} /></td>
                  <td className="max-w-[420px]"><IocValue type={i.type} value={i.value} compact onOpen={() => setOpen(idx)} /></td>
                  <td className="whitespace-nowrap">{IOC_TYPE_LABEL[i.type] ?? i.type}</td>
                  <td className="min-w-[150px]"><VerdictCell i={i} hidden={hidden} /></td>
                  <td className="max-w-[220px] truncate text-fg-muted" title={i.reputation_summary}>{i.known_good ? `Known-good: ${i.known_good}` : i.reputation_summary || "Not enriched"}</td>
                  <td className="min-w-[220px] max-w-[360px]">
                    {i.role && <div className="font-semibold break-words">{i.role}</div>}
                    {i.context && i.context !== i.role && <div className="line-clamp-2 text-body-sm text-fg-muted break-words" title={i.context}>{i.context}</div>}
                    {!i.role && !i.context && "—"}
                  </td>
                  <td className="min-w-[160px]"><SourceChips ids={i.source_ids} sources={sources} label="" compact empty="No source" /></td>
                  {canEdit && (
                    <td>
                      <Menu width={240} items={[
                        ...(["false_positive", "benign", "suspicious", "malicious"] as ReviewVerdict[]).map((v) => ({
                          label: ACTION_LABEL[v], icon: v === "false_positive" ? <ShieldX /> : v === "benign" ? <ShieldCheck /> : undefined,
                          disabled: i.analyst?.verdict === v, onSelect: () => ask([i], v),
                        })),
                        { label: "", divider: true, onSelect: () => undefined },
                        i.excluded ? { label: "Include in hunts", icon: <Ban />, onSelect: () => exclude([i], false) }
                          : { label: "Exclude from hunts", icon: <Ban />, onSelect: () => exclude([i], true) },
                        { label: "Restore pipeline verdict", icon: <RotateCcw />, disabled: !i.analyst, onSelect: () => restore([i]) },
                      ]} trigger={(p) => <button {...p} type="button" aria-label={`Verdict actions for ${defang(i.value, i.type)}`} className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-subtle hover:text-fg [&_svg]:size-4"><MoreHorizontal /></button>} />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
        {!rows.length && <p className="p-6 text-center text-fg-muted">{hiddenOnly ? "No indicator is hidden from hunts." : "No indicators match these filters."}</p>}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3 text-caption text-fg-muted">
        {canEdit ? (
          <Checkbox checked={includeExpired} disabled={busy} onChange={(v) => send([], { include_expired: v }, v ? "Expired indicators included in retro-hunts" : "Expired indicators left out of retro-hunts")}
            label={<span className="text-caption">Include expired infrastructure in retro-hunts</span>} />
        ) : <span>Expired infrastructure is {includeExpired ? "included in" : "left out of"} retro-hunts.</span>}
        <span>Expiry age per type is set in <a className="prose-link" href="/settings/osint">Settings → OSINT</a>.</span>
      </div>

      <Dialog open={!!pending} onClose={() => !busy && setPending(null)} title={pending ? `${ACTION_LABEL[pending.verdict]}: ${pending.items.length} indicator${pending.items.length === 1 ? "" : "s"}` : ""}
        description={pending && HIDDEN.has(pending.verdict) ? "They are hidden from hunt queries; the IoC retro-hunt queries are regenerated and every other query stays as it is." : "The verdict is recorded on this research as an analyst decision."}
        footer={<><Button onClick={() => setPending(null)} disabled={busy}>Cancel</Button><Button variant="primary" loading={busy} onClick={confirm}>{pending ? ACTION_LABEL[pending.verdict] : "Save"}</Button></>}>
        <div className="space-y-4">
          {pending && pending.items.length <= 5 && (
            <ul className="space-y-1">{pending.items.map((i) => <li key={key(i)} className="font-mono text-mono-sm break-all">{defang(i.value, i.type)}</li>)}</ul>
          )}
          <Field label="Note" optional htmlFor="ioc-note" help="Why: e.g. shared CDN edge, sandbox infrastructure, the vendor's own server.">
            <Textarea id="ioc-note" rows={3} value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} />
          </Field>
          <Checkbox checked={propagate} onChange={setPropagate} label="Also set this verdict in the IoC library"
            description="Becomes a library override: later runs of any research leave it out of retro-hunts." />
        </div>
      </Dialog>

      <Drawer open={!!cur} onClose={() => setOpen(null)} title={cur ? <span className="font-mono text-mono break-all">{defang(cur.value, cur.type)}</span> : ""}
        subtitle={cur ? IOC_TYPE_LABEL[cur.type] : ""} onPrev={open ? () => setOpen(open - 1) : undefined} onNext={open !== null && open < rows.length - 1 ? () => setOpen(open + 1) : undefined}>
        {cur && (
          <div className="space-y-5">
            <IocValue type={cur.type} value={cur.value} verdict={cur.verdict === "false_positive" ? "benign" : cur.verdict} sources={cur.source_ids.length} publishers={cur.source_ids.map((s) => sources[s]?.publisher ?? s)} />
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Verdict</h3>
              <div className="flex flex-wrap items-center gap-2"><AnyVerdictBadge verdict={cur.verdict} />{isHidden(cur, includeExpired) && <Badge>Hidden from hunts</Badge>}</div>
              <DecisionNote i={cur} full />
              {cur.pipeline_verdict && cur.pipeline_verdict !== cur.verdict && <p className="mt-1 text-body-sm text-fg-muted">Pipeline verdict: {VERDICT_LABEL[cur.pipeline_verdict]}</p>}
              {(cur.intel_first_seen || cur.expires_at) && (
                <p className="mt-1 text-body-sm text-fg-muted">
                  {cur.intel_first_seen && <>Intel first seen {utc(cur.intel_first_seen, false)}</>}
                  {cur.expires_at && <>{cur.intel_first_seen ? " · " : ""}{new Date(cur.expires_at) < new Date() ? "Expired" : "Expires"} {utc(cur.expires_at, false)}</>}
                </p>
              )}
              {canEdit && (
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button size="sm" icon={<ShieldX />} disabled={busy} onClick={() => ask([cur], "false_positive")}>False positive</Button>
                  <Button size="sm" icon={<ShieldCheck />} disabled={busy} onClick={() => ask([cur], "benign")}>Benign</Button>
                  <Button size="sm" icon={<Ban />} disabled={busy} onClick={() => exclude([cur], !cur.excluded)}>{cur.excluded ? "Include in hunts" : "Exclude from hunts"}</Button>
                  {cur.analyst && <Button size="sm" icon={<RotateCcw />} disabled={busy} onClick={() => restore([cur])}>Restore</Button>}
                </div>
              )}
            </div>
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Reputation</h3>
              {Object.keys(cur.reputation ?? {}).length ? (
                <div className="overflow-x-auto"><table className="tl-table tl-compact w-full"><tbody>
                  {Object.entries(cur.reputation).map(([k, v]) => <tr key={k}><td className="font-semibold">{k}</td><td>{String(v.summary ?? JSON.stringify(v))}</td></tr>)}
                </tbody></table></div>
              ) : <p className="text-fg-muted">{cur.known_good ? `On the known-good hash list: ${cur.known_good}.` : "Not enriched. Add OSINT keys in Settings, then enrich from the IoC library."}</p>}
            </div>
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Context</h3>
              {cur.role && <p className="mb-2"><Badge>{cur.role}</Badge></p>}
              <ul className="space-y-2">{(cur.contexts?.length ? cur.contexts : [cur.context]).filter(Boolean).map((c, i) => <li key={i} className="text-[14px] italic text-fg-strong break-words">“{c}”</li>)}</ul>
            </div>
            <div>
              <h3 className="mb-2 text-h4 font-semibold">Mentioned by</h3>
              <SourceChips ids={cur.source_ids} sources={sources} label="" empty="No source recorded" />
              <ul className="mt-2 space-y-1">{cur.source_ids.map((s) => sources[s] && <li key={s} className="text-body-sm text-fg-muted break-words"><span className="font-mono">{s}</span> · {sources[s].title}</li>)}</ul>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}

function VerdictCell({ i, hidden }: { i: ReviewedIoc; hidden: boolean }) {
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1">
        <AnyVerdictBadge verdict={i.verdict} />
        {i.excluded && <Tooltip content="Excluded from hunt queries by an analyst"><span><Badge>Excluded</Badge></span></Tooltip>}
        {hidden && !i.excluded && <Tooltip content="Left out of the IoC retro-hunt queries"><span className="inline-flex text-fg-muted [&_svg]:size-3.5" aria-label="Hidden from hunts"><EyeOff /></span></Tooltip>}
      </div>
      <DecisionNote i={i} />
    </div>
  );
}

/** Who decided, when, and the note: an analyst decision on this research, or a library override. */
function DecisionNote({ i, full }: { i: ReviewedIoc; full?: boolean }) {
  const a = i.analyst;
  const lo = i.verdict_source === "library" ? i.library_override : undefined;
  if (!a && !lo) return null;
  const who = a ? (a.by_name ?? a.by ?? "Analyst") : (lo?.by_name ?? lo?.by ?? "Analyst");
  const at = a ? a.at : lo?.at;
  const n = a ? a.note : lo?.note;
  return (
    <div className={full ? "mt-2 text-body-sm text-fg-muted" : "text-caption text-fg-muted"}>
      <span title={at ? utc(at) : undefined}>{lo ? "Library override · " : ""}{who}{at ? ` · ${relative(at)}` : ""}</span>
      {n && (full ? <p className="mt-1 italic text-fg-strong break-words">“{n}”</p> : <span className="block max-w-[220px] truncate italic" title={n}>“{n}”</span>)}
    </div>
  );
}
