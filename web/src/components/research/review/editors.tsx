"use client";

import clsx from "clsx";
import { ArrowDown, ArrowUp, Check, Pencil, Plus, Search, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, patch, post, put } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import type { Source } from "@/lib/types";
import { Button } from "../../ui/button";
import { useToast } from "../../ui/feedback";
import { Field, Input, MultiSelect, Select, Textarea } from "../../ui/forms";
import { Dialog } from "../../ui/overlay";
import type { AttackPathE, MitreRowE } from "./readiness";

interface Catalog { tactics: { id: string; name: string }[]; techniques: { id: string; name: string; tactic_ids: string[] }[] }

const CONFIDENCE = [{ value: "low", label: "Low" }, { value: "moderate", label: "Moderate" }, { value: "high", label: "High" }];

function useSaver() {
  const toast = useToast();
  const [saving, setSaving] = useState(false);
  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setSaving(true);
    try {
      await fn();
      toast({ tone: "success", message: ok });
      return true;
    } catch (e) {
      toast({ tone: "danger", message: (e as Error).message });
      return false;
    } finally { setSaving(false); }
  };
  return { saving, run };
}

/** Pick report sources by id (S1, S2…). */
export function SourcePicker({ id, sources, values, onChange }: { id?: string; sources: Source[]; values: string[]; onChange: (v: string[]) => void }) {
  return (
    <MultiSelect id={id} ariaLabel="Sources" values={values} onChange={onChange} placeholder="Cite at least one source…" invalid={!values.length}
      options={sources.map((s) => ({ value: s.id, label: `${s.id} · ${s.publisher || s.title}`, hint: s.title }))} />
  );
}

/** Inline title editor for the research header. */
export function InlineTitle({ rid, title, canEdit, onSaved, className }: { rid: string; title: string; canEdit: boolean; onSaved: () => Promise<void> | void; className?: string }) {
  const [editing, setEditing] = useState(false);
  const [v, setV] = useState(title);
  const { saving, run } = useSaver();
  useEffect(() => setV(title), [title, editing]);
  const save = async () => {
    const t = v.trim().replace(/\s+/g, " ");
    if (!t || t === title) { setEditing(false); return; }
    if (await run(() => patch(`/api/research/${rid}/title`, { title: t }), "Title saved")) { setEditing(false); await onSaved(); }
  };
  if (!editing) {
    return (
      <div className="group flex min-w-0 items-start gap-2">
        <h1 className={className}>{title}</h1>
        {canEdit && (
          <button type="button" onClick={() => setEditing(true)} aria-label="Edit title"
            className="mt-2 grid size-8 shrink-0 place-items-center rounded-sm text-fg-muted opacity-70 hover:bg-subtle hover:text-fg group-hover:opacity-100 focus-visible:opacity-100">
            <Pencil className="size-4" />
          </button>
        )}
      </div>
    );
  }
  return (
    <form className="flex min-w-0 flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <Input value={v} onChange={(e) => setV(e.target.value)} aria-label="Research title" autoFocus maxLength={200} inputSize="lg"
        className="min-w-0 flex-1 text-h2 font-semibold" onKeyDown={(e) => { if (e.key === "Escape") setEditing(false); }} />
      <Button type="submit" variant="primary" icon={<Check />} loading={saving} disabled={v.trim().length < 3} disabledReason="At least 3 characters">Save</Button>
      <Button type="button" icon={<X />} onClick={() => setEditing(false)}>Cancel</Button>
    </form>
  );
}

/** Add or edit one MITRE ATT&CK row. `index` is the row's position in record.mitre (omit to add). */
export function MitreDialog({ open, onClose, rid, sources, row, index, onSaved }:
  { open: boolean; onClose: () => void; rid: string; sources: Source[]; row?: MitreRowE; index?: number; onSaved: () => Promise<void> | void }) {
  const { data: cat } = useApi<Catalog>(open ? "/api/attack/techniques" : null);
  const [q, setQ] = useState("");
  const [tid, setTid] = useState("");
  const [tactic, setTactic] = useState("");
  const [procedure, setProcedure] = useState("");
  const [quote, setQuote] = useState("");
  const [sids, setSids] = useState<string[]>([]);
  const [conf, setConf] = useState("moderate");
  const { saving, run } = useSaver();

  useEffect(() => {
    if (!open) return;
    setQ(""); setTid(row?.technique_id ?? ""); setTactic(row?.tactic_id ?? ""); setProcedure(row?.procedure ?? "");
    setQuote(row?.evidence_quote ?? ""); setSids(row?.source_ids ?? []); setConf(row?.confidence || "moderate");
  }, [open, row]);

  const tech = cat?.techniques.find((t) => t.id === tid);
  const tacticName = (id: string) => cat?.tactics.find((t) => t.id === id)?.name ?? id;
  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!cat || !s) return [];
    return cat.techniques.filter((t) => t.id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s))
      .sort((a, b) => Number(!a.id.toLowerCase().startsWith(s)) - Number(!b.id.toLowerCase().startsWith(s)) || a.id.localeCompare(b.id)).slice(0, 8);
  }, [cat, q]);

  const pick = (t: Catalog["techniques"][number]) => {
    setTid(t.id);
    setTactic(t.tactic_ids.includes(tactic) ? tactic : t.tactic_ids[0] ?? "");
    setQ("");
  };
  const missing = !tid ? "Pick a technique" : !sids.length ? "Cite at least one source (unsupported rows block publishing)" : !quote.trim() ? "Add the evidence quote from the source" : "";
  const save = async () => {
    const body = { technique_id: tid, tactic_id: tactic || null, procedure, evidence_quote: quote, source_ids: sids, confidence: conf };
    const ok = await run(() => (index === undefined
      ? post(`/api/research/${rid}/mitre`, body)
      : put(`/api/research/${rid}/mitre/${index}?expect=${encodeURIComponent(row?.technique_id ?? "")}`, body)),
    index === undefined ? `Added ${tid}` : `Saved ${tid}`);
    if (ok) { onClose(); await onSaved(); }
  };

  return (
    <Dialog open={open} onClose={onClose} size="lg" title={index === undefined ? "Add MITRE ATT&CK technique" : `Edit ${row?.technique_id}`}
      description="Technique IDs are checked against the ATT&CK Enterprise catalog. Quote the source verbatim."
      footer={<>
        {missing && <span className="mr-auto self-center text-caption text-fg-muted">{missing}</span>}
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={saving} disabled={!tid} disabledReason="Pick a technique" onClick={save}>{index === undefined ? "Add technique" : "Save row"}</Button>
      </>}>
      <div className="space-y-5">
        <Field label="Technique" htmlFor="mitre-q" help={tech ? undefined : "Search by ID (T1059.001) or name (PowerShell)."}>
          <div className="space-y-2">
            {tech && (
              <div className="flex flex-wrap items-center gap-2 rounded-sm border border-line bg-subtle px-3 py-2">
                <span className="font-mono text-mono-sm font-semibold text-accent-text">{tech.id}</span>
                <span className="min-w-0 flex-1 text-[14px]">{tech.name}</span>
              </div>
            )}
            {tid && !tech && cat && <p className="text-body-sm text-danger">{tid} is not in the current ATT&CK catalog.</p>}
            <Input id="mitre-q" value={q} onChange={(e) => setQ(e.target.value)} prefixIcon={<Search className="size-4" />} placeholder={tech ? "Search to change technique…" : "Search techniques…"}
              role="combobox" aria-expanded={results.length > 0} aria-controls="mitre-results" autoComplete="off" data-autofocus={index === undefined ? true : undefined}
              onKeyDown={(e) => { if (e.key === "Enter" && results[0]) { e.preventDefault(); pick(results[0]); } }} />
            {results.length > 0 && (
              <ul id="mitre-results" role="listbox" aria-label="Matching techniques" className="max-h-64 overflow-y-auto rounded-sm border border-line bg-raised">
                {results.map((t) => (
                  <li key={t.id} role="option" aria-selected={t.id === tid}>
                    <button type="button" onClick={() => pick(t)} className="flex w-full items-baseline gap-2 px-3 py-1.5 text-left hover:bg-subtle">
                      <span className="w-20 shrink-0 font-mono text-mono-sm font-semibold text-accent-text">{t.id}</span>
                      <span className="min-w-0 flex-1 text-[14px]">{t.name}</span>
                      <span className="shrink-0 text-caption text-fg-muted">{t.tactic_ids.map(tacticName).join(", ")}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Tactic" htmlFor="mitre-tactic" help={tech && tech.tactic_ids.length > 1 ? "This technique serves several tactics; pick the one this procedure serves." : undefined}>
            <Select id="mitre-tactic" value={tactic} onChange={setTactic} disabled={!tech || tech.tactic_ids.length < 2}
              options={(tech?.tactic_ids ?? (tactic ? [tactic] : [""])).map((t) => ({ value: t, label: t ? tacticName(t) : "Derived from the technique" }))} />
          </Field>
          <Field label="Confidence" htmlFor="mitre-conf"><Select id="mitre-conf" value={conf} onChange={setConf} options={CONFIDENCE} /></Field>
        </div>
        <Field label="Procedure" htmlFor="mitre-proc" help="One sentence in this threat's terms.">
          <Textarea id="mitre-proc" value={procedure} onChange={(e) => setProcedure(e.target.value)} rows={2} className="!min-h-[60px]" />
        </Field>
        <Field label="Evidence quote" htmlFor="mitre-quote" help="Verbatim from the cited source (max ~25 words). It is checked against the stored article text.">
          <Textarea id="mitre-quote" value={quote} onChange={(e) => setQuote(e.target.value)} rows={2} className="!min-h-[60px]" />
        </Field>
        <Field label="Sources" htmlFor="mitre-src"><SourcePicker id="mitre-src" sources={sources} values={sids} onChange={setSids} /></Field>
      </div>
    </Dialog>
  );
}

export async function deleteMitre(rid: string, index: number, tid: string) {
  return api(`/api/research/${rid}/mitre/${index}?expect=${encodeURIComponent(tid)}`, { method: "DELETE" });
}

type StepDraft = { key: string; ref?: string; behaviour: string; technique_id: string; source_ids: string[] };

/** Rename an attack path and add / edit / remove / reorder its steps. Saved as one versioned edit. */
export function AttackPathDialog({ open, onClose, rid, path, sources, onSaved }:
  { open: boolean; onClose: () => void; rid: string; path: AttackPathE | null; sources: Source[]; onSaved: () => Promise<void> | void }) {
  const [name, setName] = useState("");
  const [steps, setSteps] = useState<StepDraft[]>([]);
  const { saving, run } = useSaver();
  const { data: cat } = useApi<Catalog>(open ? "/api/attack/techniques" : null);
  const known = useMemo(() => new Set(cat?.techniques.map((t) => t.id) ?? []), [cat]);

  useEffect(() => {
    if (!open) return;
    setName(path?.name ?? "");
    setSteps((path?.steps ?? []).map((s, j) => ({ key: s.ref || `${path?.id}.${j + 1}`, ref: s.ref || `${path?.id}.${j + 1}`, behaviour: s.behaviour, technique_id: s.technique_id, source_ids: s.source_ids ?? [] })));
  }, [open, path]);

  const upd = (i: number, p: Partial<StepDraft>) => setSteps(steps.map((s, j) => (j === i ? { ...s, ...p } : s)));
  const move = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= steps.length) return;
    const next = [...steps];
    [next[i], next[j]] = [next[j], next[i]];
    setSteps(next);
  };
  const badTech = steps.filter((s) => s.technique_id.trim() && cat && !known.has(s.technique_id.trim().toUpperCase()));
  const empty = steps.some((s) => !s.behaviour.trim());
  const save = async () => {
    const body = { name, steps: steps.map((s) => ({ ref: s.ref, behaviour: s.behaviour, technique_id: s.technique_id.trim().toUpperCase(), source_ids: s.source_ids })) };
    const ok = path
      ? await run(() => put(`/api/research/${rid}/attack-paths/${path.id}`, body), `Saved ${path.id}`)
      : await run(() => post(`/api/research/${rid}/attack-paths`, body), "Attack path added");
    if (ok) { onClose(); await onSaved(); }
  };
  const reason = !name.trim() ? "Name the path" : empty ? "Every step needs a behaviour" : badTech.length ? `Unknown technique: ${badTech.map((s) => s.technique_id).join(", ")}` : undefined;

  return (
    <Dialog open={open} onClose={onClose} size="lg" title={path ? `Edit attack path ${path.id}` : "Add attack path"}
      description="Existing steps keep their reference (detection opportunities point at it). Steps without a source are flagged unsupported."
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={saving} disabled={!!reason} disabledReason={reason} onClick={save}>Save path</Button>
      </>}>
      <div className="space-y-4">
        <Field label="Path name" htmlFor="ap-name"><Input id="ap-name" value={name} onChange={(e) => setName(e.target.value)} data-autofocus /></Field>
        <ol className="space-y-3" aria-label="Steps">
          {steps.map((s, i) => {
            const bad = !!s.technique_id.trim() && !!cat && !known.has(s.technique_id.trim().toUpperCase());
            return (
              <li key={s.key} className="rounded-md border border-line p-3">
                <div className="mb-2 flex items-center gap-2">
                  <span className="font-mono text-mono-sm text-fg-muted">{s.ref ?? "new"}</span>
                  <span className="text-caption text-fg-muted">Step {i + 1}</span>
                  <div className="ml-auto flex items-center gap-1">
                    <button type="button" onClick={() => move(i, -1)} disabled={i === 0} aria-label={`Move step ${i + 1} up`} className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-subtle disabled:opacity-40"><ArrowUp className="size-4" /></button>
                    <button type="button" onClick={() => move(i, 1)} disabled={i === steps.length - 1} aria-label={`Move step ${i + 1} down`} className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-subtle disabled:opacity-40"><ArrowDown className="size-4" /></button>
                    <button type="button" onClick={() => setSteps(steps.filter((_, j) => j !== i))} aria-label={`Remove step ${i + 1}`} className="grid size-7 place-items-center rounded-sm text-fg-muted hover:bg-danger-soft hover:text-danger"><Trash2 className="size-4" /></button>
                  </div>
                </div>
                <div className="grid gap-2 sm:grid-cols-[1fr_140px]">
                  <Textarea value={s.behaviour} onChange={(e) => upd(i, { behaviour: e.target.value })} rows={2} className="!min-h-[52px]" aria-label={`Step ${i + 1} behaviour`} placeholder="Observed behaviour" invalid={!s.behaviour.trim()} />
                  <Input value={s.technique_id} onChange={(e) => upd(i, { technique_id: e.target.value })} aria-label={`Step ${i + 1} technique ID`} placeholder="T1059.001" className="font-mono" invalid={bad} list="ap-techniques" />
                </div>
                {bad && <p className="mt-1 text-caption text-danger">{s.technique_id} is not in the ATT&CK catalog.</p>}
                <div className="mt-2"><SourcePicker sources={sources} values={s.source_ids} onChange={(v) => upd(i, { source_ids: v })} /></div>
              </li>
            );
          })}
        </ol>
        <datalist id="ap-techniques">{cat?.techniques.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</datalist>
        <Button icon={<Plus />} onClick={() => setSteps([...steps, { key: `new-${Date.now()}`, behaviour: "", technique_id: "", source_ids: [] }])}>Add step</Button>
      </div>
    </Dialog>
  );
}

export function EditedMark({ className }: { className?: string }) {
  return <span className={clsx("ml-1 inline-flex h-[18px] items-center rounded-xs bg-[var(--neutral-chip-bg)] px-1.5 align-middle text-[11px] font-semibold text-[var(--neutral-chip-text)]", className)} title="Edited by a person">Edited</span>;
}
