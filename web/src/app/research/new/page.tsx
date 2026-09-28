"use client";

import clsx from "clsx";
import { Check, Info } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { useApp, useWsHref } from "@/components/providers";
import { Chip } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Alert, useToast } from "@/components/ui/feedback";
import { ChipInput, Field, MultiSelect, Segmented, Select, Textarea, Toggle } from "@/components/ui/forms";
import { Page, PageHeader } from "@/components/ui/layout";
import { Dialog } from "@/components/ui/overlay";
import { post } from "@/lib/api";
import { CLASSIFICATION, TLPS } from "@/lib/constants";
import { useDebounced } from "@/lib/hooks";

const DEPTHS = [
  { value: "quick", label: "Quick (5)" },
  { value: "standard", label: "Standard (10)" },
  { value: "deep", label: "Deep (15+)" },
] as const;

function detect(seed: string) {
  const cves = Array.from(new Set((seed.match(/CVE-\d{4}-\d{4,7}/gi) ?? []).map((c) => c.toUpperCase())));
  const urls = Array.from(new Set(seed.match(/https?:\/\/[^\s<>"')\]]+/g) ?? []));
  const actorPats = [/\bStorm-\d{4}\b/g, /\bAPT ?\d{1,3}\b/g, /\bUNC\d{3,5}\b/g, /\bTA\d{3,4}\b/g, /\bFIN\d{1,2}\b/g, /\bCL-[A-Z]{3}-\d{4}\b/g,
    /\b[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest)\b/g, /\b[A-Z][a-z]+ (?:Panda|Bear|Kitten|Chollima|Spider)\b/g];
  const actors = Array.from(new Set(actorPats.flatMap((p) => seed.match(p) ?? [])));
  return { cves, urls, actors };
}

export default function NewResearch() {
  const { workspaces, activeWorkspace, meta } = useApp();
  const router = useRouter();
  const wsHref = useWsHref();
  const toast = useToast();
  const [seed, setSeed] = useState("");
  const [removed, setRemoved] = useState<string[]>([]);
  const [seedUrls, setSeedUrls] = useState<string[]>([]);
  const [wsIds, setWsIds] = useState<string[]>([]);
  const [platforms, setPlatforms] = useState<string[]>([]);
  const [touchedPlatforms, setTouchedPlatforms] = useState(false);
  const [vendors, setVendors] = useState<string[] | null>(null);
  const [openWeb, setOpenWeb] = useState(true);
  const [depth, setDepth] = useState<"quick" | "standard" | "deep">("standard");
  const [lookback, setLookback] = useState("30");
  const [tlp, setTlp] = useState("AMBER");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState<"start" | "draft" | null>(null);
  const [dups, setDups] = useState<{ id: string; title: string; status: string; reason: string }[]>([]);
  const [dirty, setDirty] = useState(false);
  const [leaveTo, setLeaveTo] = useState<string | null>(null);
  const summaryRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (activeWorkspace && !wsIds.length) setWsIds([activeWorkspace.id]);
    if (!activeWorkspace && workspaces.length && !wsIds.length) setWsIds([workspaces[0].id]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWorkspace, workspaces]);

  const defaults = useMemo(() => Array.from(new Set(workspaces.filter((w) => wsIds.includes(w.id)).flatMap((w) => w.platforms))), [workspaces, wsIds]);
  useEffect(() => { if (!touchedPlatforms) setPlatforms(defaults); }, [defaults, touchedPlatforms]);
  useEffect(() => {
    const w = workspaces.find((x) => x.id === wsIds[0]);
    if (w) setTlp(w.default_tlp || "AMBER");
  }, [wsIds, workspaces]);
  useEffect(() => { if (meta && vendors === null) setVendors(meta.vendors.map((v) => v.id)); }, [meta, vendors]);

  const dseed = useDebounced(seed, 300);
  const found = useMemo(() => detect(dseed), [dseed]);
  const chips = [
    ...found.cves.map((c) => ({ key: c, label: c, dot: CLASSIFICATION.cve.color })),
    ...found.actors.map((a) => ({ key: a, label: a, dot: CLASSIFICATION.actor.color })),
    ...(found.urls.length ? [{ key: "urls", label: `${found.urls.length} URL${found.urls.length > 1 ? "s" : ""}`, dot: CLASSIFICATION.intel.color }] : []),
  ].filter((c) => !removed.includes(c.key));

  useEffect(() => {
    if (!dseed.trim() && !seedUrls.length) { setDups([]); return; }
    post<{ matches: typeof dups }>("/api/research/check-duplicates", { seed: dseed, seed_urls: seedUrls }).then((r) => setDups(r.matches)).catch(() => undefined);
  }, [dseed, seedUrls]);

  useEffect(() => {
    const h = (e: BeforeUnloadEvent) => { if (dirty && !submitting) { e.preventDefault(); } };
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [dirty, submitting]);

  const validUrl = (u: string) => (/^https?:\/\/[^\s.]+\.[^\s]+$/.test(u) ? null : "Not a valid URL");

  const validate = () => {
    const e: Record<string, string> = {};
    if (seed.trim().length < 3) e.seed = "Paste a threat headline, CVE, actor, campaign or article URL";
    if (!wsIds.length) e.workspaces = "Select at least one workspace";
    if (!platforms.length) e.platforms = "Select at least one output platform";
    const bad = seedUrls.filter((u) => validUrl(u));
    if (bad.length) e.seed_urls = `Fix or remove ${bad.length} invalid URL${bad.length > 1 ? "s" : ""}`;
    setErrors(e);
    if (Object.keys(e).length) setTimeout(() => summaryRef.current?.focus(), 0);
    return !Object.keys(e).length;
  };

  const submit = async (draft: boolean) => {
    if (!validate()) return;
    setSubmitting(draft ? "draft" : "start");
    try {
      const allUrls = Array.from(new Set([...seedUrls, ...(removed.includes("urls") ? [] : found.urls)]));
      const r = await post<{ id: string; run_id: string; mode: string }>("/api/research", {
        seed, seed_urls: allUrls, workspace_ids: wsIds, platforms, vendors, open_web: openWeb, depth, lookback_days: Number(lookback), tlp, draft,
      });
      setDirty(false);
      toast({ tone: "success", message: draft ? `Saved ${r.id} as draft` : `Research started${r.mode === "offline" ? " (offline mode — no LLM key configured)" : ""}` });
      router.push(wsHref(draft ? `/research/${r.id}` : `/research/${r.id}/run`));
    } catch (e) {
      toast({ tone: "danger", message: (e as Error).message });
    } finally {
      setSubmitting(null);
    }
  };

  const go = (href: string) => (dirty ? setLeaveTo(href) : router.push(href));

  return (
    <Page className="pb-28">
      <PageHeader crumbs={[{ label: "Research", href: "/research" }, { label: "New run" }]} title="Start research"
        description="Turn a threat headline into a configured run. The pipeline collects sources, reads them and builds a draft report." />
      <div className="max-w-form space-y-8">
        {Object.keys(errors).length > 0 && (
          <div ref={summaryRef} tabIndex={-1}>
            <Alert tone="danger" title="Fix these before starting">
              <ul className="mt-1 list-disc pl-5">
                {Object.entries(errors).map(([k, v]) => <li key={k}><a href={`#${k}`} className="prose-link">{v}</a></li>)}
              </ul>
            </Alert>
          </div>
        )}
        {meta && !meta.llm.available && (
          <Alert tone="info" title="Offline mode">
            No Anthropic API key is configured on the API server, so the pipeline uses regex and heuristics. Set <code className="font-mono">ANTHROPIC_API_KEY</code> for full synthesis.
          </Alert>
        )}

        <section className="rounded-md border border-line bg-surface p-4 sm:p-6">
          <h3 className="mb-1 text-h3 font-semibold">Threat</h3>
          <p className="mb-5 text-body-sm text-fg-muted">Paste an email body, headline, CVE, actor or campaign name.</p>
          <div className="space-y-5">
            <Field label="Threat seed" htmlFor="seed" error={errors.seed}>
              <Textarea id="seed" autoGrow value={seed} invalid={!!errors.seed} aria-describedby={errors.seed ? "seed-error" : undefined}
                placeholder="e.g. CVE-2025-53770 or a vendor article URL"
                onChange={(e) => { setSeed(e.target.value); setDirty(true); }} onBlur={() => errors.seed && validate()} />
              {chips.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <span className="text-caption text-fg-muted">Detected:</span>
                  {chips.map((c) => <Chip key={c.key} dot={c.dot} onRemove={() => setRemoved([...removed, c.key])}>{c.label}</Chip>)}
                </div>
              )}
            </Field>
            <Field label="Seed URLs" optional htmlFor="seed_urls" help="Always included as sources. Paste several at once." error={errors.seed_urls}>
              <ChipInput id="seed_urls" values={seedUrls} onChange={(v) => { setSeedUrls(v); setDirty(true); }} validate={validUrl} placeholder="https://… then Enter" />
            </Field>
            {dups.map((d) => (
              <Alert key={d.id} tone="info" title={`A ${d.status.replace("_", " ")} report exists: ${d.id}`}
                action={<div className="flex flex-wrap gap-2 text-[14px]">
                  <Link className="prose-link" href={wsHref(`/research/${d.id}`)}>Open it</Link>
                  <Link className="prose-link" href={wsHref(`/research/${d.id}?rerun=1`)}>Re-run it</Link>
                  <span className="text-fg-muted">or start new below</span>
                </div>}>
                {d.title} — {d.reason}.
              </Alert>
            ))}
          </div>
        </section>

        <section className="rounded-md border border-line bg-surface p-4 sm:p-6">
          <h3 className="mb-1 text-h3 font-semibold">Output</h3>
          <p className="mb-5 text-body-sm text-fg-muted">Workspaces decide default platforms, field mappings and report branding.</p>
          <div className="space-y-5">
            <Field label="Workspaces" htmlFor="workspaces" error={errors.workspaces}>
              <MultiSelect id="workspaces" ariaLabel="Workspaces" values={wsIds} invalid={!!errors.workspaces}
                onChange={(v) => { setWsIds(v); setDirty(true); }}
                options={workspaces.map((w) => ({ value: w.id, label: w.name, hint: w.industry, color: w.color }))} />
            </Field>
            <fieldset id="platforms">
              <legend className="mb-1.5 text-[13px] font-semibold">Output platforms</legend>
              <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
                {(meta?.platforms ?? []).map((p) => {
                  const on = platforms.includes(p.id);
                  return (
                    <label key={p.id} className={clsx("flex h-14 cursor-pointer items-center gap-3 rounded-md border px-3 transition-colors",
                      on ? "border-accent bg-accent-soft" : "border-line bg-surface hover:border-line-hover")}>
                      <input type="checkbox" className="sr-only" checked={on} onChange={() => { setTouchedPlatforms(true); setDirty(true); setPlatforms(on ? platforms.filter((x) => x !== p.id) : [...platforms, p.id]); }} />
                      <span className={clsx("grid size-4 shrink-0 place-items-center rounded-xs border", on ? "border-accent bg-accent" : "border-line-hover bg-surface")}>
                        {on && <Check className="size-3 text-white" strokeWidth={3} />}
                      </span>
                      <PlatformGlyph id={p.id} />
                      <span className="min-w-0">
                        <span className="block truncate text-[14px] font-semibold">{p.name}</span>
                        {defaults.includes(p.id) && <span className="block text-caption text-fg-muted">Workspace default</span>}
                      </span>
                    </label>
                  );
                })}
              </div>
              {errors.platforms && <p className="mt-1 text-caption text-danger">{errors.platforms}</p>}
            </fieldset>
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Hunt look-back" htmlFor="lookback">
                <Select id="lookback" value={lookback} onChange={setLookback} options={["7", "14", "30", "90"].map((d) => ({ value: d, label: `${d} days` }))} />
              </Field>
              <Field label="TLP" htmlFor="tlp">
                <Select id="tlp" value={tlp} onChange={setTlp} options={TLPS.map((t) => ({ value: t, label: `TLP:${t}` }))} />
              </Field>
            </div>
          </div>
        </section>

        <section className="rounded-md border border-line bg-surface p-4 sm:p-6">
          <h3 className="mb-1 text-h3 font-semibold">Research depth</h3>
          <p className="mb-5 text-body-sm text-fg-muted">More sources take longer and cost more; Standard targets under 10 minutes.</p>
          <div className="space-y-5">
            <Segmented ariaLabel="Depth" value={depth} onChange={(v) => setDepth(v)} options={DEPTHS.map((d) => ({ value: d.value, label: d.label }))} />
            <div>
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[13px] font-semibold">Source preference</span>
                <button className="text-[13px] font-semibold text-accent-text hover:underline" onClick={() => setVendors(vendors?.length === meta?.vendors.length ? [] : meta?.vendors.map((v) => v.id) ?? [])}>
                  {vendors?.length === meta?.vendors.length ? "Turn all off" : "Turn all on"}
                </button>
              </div>
              <div className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
                {(meta?.vendors ?? []).map((v) => (
                  <Toggle key={v.id} checked={vendors?.includes(v.id) ?? true} label={v.name}
                    onChange={(c) => setVendors(c ? [...(vendors ?? []), v.id] : (vendors ?? []).filter((x) => x !== v.id))} />
                ))}
                <Toggle checked={openWeb} onChange={setOpenWeb} label="Open web" />
              </div>
              {meta && !meta.search.available && (
                <p className="mt-3 flex items-start gap-1.5 text-caption text-fg-muted"><Info className="mt-px size-3.5 shrink-0" />Open-web search needs BRAVE_SEARCH_API_KEY on the API server. Vendor feeds and seed URLs still work.</p>
              )}
            </div>
          </div>
        </section>
      </div>

      <div className="fixed right-0 bottom-0 left-0 z-[150] border-t border-line bg-surface sm:left-16 lg:left-[var(--sb,240px)]">
        <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-end gap-3 px-4 md:px-6">
          <Button onClick={() => go(wsHref("/research"))}>Cancel</Button>
          <Button onClick={() => submit(true)} loading={submitting === "draft"}>Save as draft</Button>
          <Button variant="primary" size="lg" onClick={() => submit(false)} loading={submitting === "start"}
            disabled={!platforms.length} disabledReason="Select at least one output platform">Start research</Button>
        </div>
      </div>

      <Dialog open={!!leaveTo} onClose={() => setLeaveTo(null)} size="sm" title="Discard changes to this run?"
        footer={<><Button onClick={() => setLeaveTo(null)}>Keep editing</Button><Button variant="danger" onClick={() => { const to = leaveTo!; setLeaveTo(null); setDirty(false); router.push(to); }}>Discard</Button></>}>
        <p>The seed and settings you entered will be lost.</p>
      </Dialog>
    </Page>
  );
}

/** Monochrome platform mark (logos are always shown in monochrome, tinted to secondary text). */
function PlatformGlyph({ id }: { id: string }) {
  const letters: Record<string, string> = { spl: "SPL", kql_sentinel: "KQL", kql_defender: "MDE", cql: "CQL", s1ql: "S1", xql: "XQL", esql: "ES", yaral: "YL", aql: "AQL", sigma: "Σ" };
  return <span className="grid h-6 min-w-8 place-items-center rounded-xs border border-line px-1 font-mono text-[10px] font-bold text-fg-muted">{letters[id] ?? id}</span>;
}
