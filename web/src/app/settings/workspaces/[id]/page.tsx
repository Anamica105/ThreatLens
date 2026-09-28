"use client";

import clsx from "clsx";
import { Check, Plus, Trash2, Upload } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useApp } from "@/components/providers";
import { Button } from "@/components/ui/button";
import { Alert, useToast } from "@/components/ui/feedback";
import { Checkbox, ChipInput, Field, Input, Select, Textarea } from "@/components/ui/forms";
import { Page, PageHeader } from "@/components/ui/layout";
import { getUserId, post, put } from "@/lib/api";
import { CATEGORICAL, DATA_SOURCES, TLPS } from "@/lib/constants";
import type { Workspace } from "@/lib/types";

const EMPTY: Omit<Workspace, "id"> = { name: "", industry: "", color: CATEGORICAL[0], platforms: ["sigma"], field_mappings: {}, log_sources: ["process_creation", "file_event", "network", "dns"], products: [], branding: {}, default_tlp: "AMBER" };

export default function WorkspaceEdit() {
  const { id } = useParams<{ id: string }>();
  const isNew = id === "new";
  const router = useRouter();
  const toast = useToast();
  const { workspaces, meta, reloadWorkspaces } = useApp();
  const existing = workspaces.find((w) => w.id === id);
  const [f, setF] = useState<Omit<Workspace, "id">>(EMPTY);
  const [mappings, setMappings] = useState<{ platform: string; from: string; to: string }[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const fileRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (existing) {
      setF({ ...existing });
      setMappings(Object.entries(existing.field_mappings ?? {}).flatMap(([p, m]) => Object.entries(m).map(([from, to]) => ({ platform: p, from, to }))));
    }
  }, [existing]);

  const save = async () => {
    const e: Record<string, string> = {};
    if (f.name.trim().length < 2) e.name = "Enter the client name";
    if (!f.platforms.length) e.platforms = "Select at least one output platform";
    setErrors(e);
    if (Object.keys(e).length) return;
    setSaving(true);
    const field_mappings: Record<string, Record<string, string>> = {};
    mappings.filter((m) => m.from.trim()).forEach((m) => { (field_mappings[m.platform] ??= {})[m.from] = m.to; });
    const body = { name: f.name, industry: f.industry, color: f.color, platforms: f.platforms, field_mappings, log_sources: f.log_sources, products: f.products, branding: { primary: f.color, disclaimer: f.branding.disclaimer ?? "" }, default_tlp: f.default_tlp };
    try {
      const w = isNew ? await post<Workspace>("/api/workspaces", body) : await put<Workspace>(`/api/workspaces/${id}`, body);
      await reloadWorkspaces();
      toast({ tone: "success", message: `Saved ${w.name}` });
      router.push("/settings/workspaces");
    } catch (err) { toast({ tone: "danger", message: (err as Error).message }); } finally { setSaving(false); }
  };

  const uploadLogo = async (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`/api/workspaces/${id}/logo`, { method: "POST", body: fd, headers: getUserId() ? { "X-User": getUserId()! } : {} });
    if (!res.ok) { toast({ tone: "danger", message: (await res.json()).detail ?? "Upload failed" }); return; }
    await reloadWorkspaces();
    toast({ tone: "success", message: "Logo uploaded" });
  };

  if (!isNew && !existing && workspaces.length) return <Page><Alert tone="danger" title="Workspace not found" /></Page>;
  return (
    <Page className="pb-28">
      <PageHeader crumbs={[{ label: "Settings", href: "/settings" }, { label: "Workspaces", href: "/settings/workspaces" }, { label: isNew ? "New" : f.name }]}
        title={isNew ? "New workspace" : f.name || "Workspace"} />
      <div className="max-w-form space-y-8">
        <section className="space-y-5 rounded-md border border-line bg-surface p-6">
          <h3 className="text-h3 font-semibold">Client</h3>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Name" htmlFor="w-name" error={errors.name}><Input id="w-name" value={f.name} invalid={!!errors.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
            <Field label="Industry" htmlFor="w-ind"><Input id="w-ind" value={f.industry} onChange={(e) => setF({ ...f, industry: e.target.value })} placeholder="e.g. Banking" /></Field>
          </div>
          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Colour tag</legend>
            <div className="flex gap-2">
              {CATEGORICAL.map((c) => (
                <button key={c} type="button" onClick={() => setF({ ...f, color: c })} aria-label={`Colour ${c}`} aria-pressed={f.color === c}
                  className={clsx("grid size-8 place-items-center rounded-full", f.color === c && "ring-2 ring-offset-2 ring-[var(--focus-ring)] ring-offset-[var(--bg-surface)]")} style={{ background: c }}>
                  {f.color === c && <Check className="size-4 text-white" />}
                </button>
              ))}
            </div>
          </fieldset>
          <Field label="Technology in scope" htmlFor="w-prod" help="Drives applicability: research on products this client doesn't run is marked Not applicable.">
            <ChipInput id="w-prod" values={f.products} onChange={(v) => setF({ ...f, products: v })} placeholder="e.g. SharePoint Server 2019, then Enter" />
          </Field>
        </section>

        <section className="space-y-5 rounded-md border border-line bg-surface p-6">
          <h3 className="text-h3 font-semibold">Hunting</h3>
          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Output platforms</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {(meta?.platforms ?? []).map((p) => (
                <Checkbox key={p.id} checked={f.platforms.includes(p.id)} label={p.name}
                  onChange={(v) => setF({ ...f, platforms: v ? [...f.platforms, p.id] : f.platforms.filter((x) => x !== p.id) })} />
              ))}
            </div>
            {errors.platforms && <p className="mt-1 text-caption text-danger">{errors.platforms}</p>}
          </fieldset>
          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Log sources available</legend>
            <p className="mb-2 text-caption text-fg-muted">Queries needing a source the client lacks show a coverage gap.</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {Object.entries(DATA_SOURCES).map(([k, label]) => (
                <Checkbox key={k} checked={f.log_sources.includes(k)} label={label}
                  onChange={(v) => setF({ ...f, log_sources: v ? [...f.log_sources, k] : f.log_sources.filter((x) => x !== k) })} />
              ))}
            </div>
          </fieldset>
          <div>
            <div className="mb-1.5 text-[13px] font-semibold">Field mappings</div>
            <p className="mb-2 text-caption text-fg-muted">Text replaced in copied queries so they are paste-ready, e.g. <code className="font-mono">index=endpoint</code> → <code className="font-mono">index=acme_edr</code>.</p>
            <div className="space-y-2">
              {mappings.map((m, i) => (
                <div key={i} className="grid grid-cols-[140px_1fr_1fr_auto] gap-2">
                  <Select value={m.platform} onChange={(v) => setMappings(mappings.map((x, j) => (j === i ? { ...x, platform: v } : x)))} ariaLabel="Platform"
                    options={(meta?.platforms ?? []).map((p) => ({ value: p.id, label: p.short }))} />
                  <Input value={m.from} placeholder="From" aria-label="From" className="font-mono" onChange={(e) => setMappings(mappings.map((x, j) => (j === i ? { ...x, from: e.target.value } : x)))} />
                  <Input value={m.to} placeholder="To" aria-label="To" onChange={(e) => setMappings(mappings.map((x, j) => (j === i ? { ...x, to: e.target.value } : x)))} />
                  <button onClick={() => setMappings(mappings.filter((_, j) => j !== i))} aria-label="Remove mapping" className="grid size-9 place-items-center rounded-sm text-fg-muted hover:bg-danger-soft hover:text-danger"><Trash2 className="size-4" /></button>
                </div>
              ))}
              <Button size="sm" icon={<Plus />} onClick={() => setMappings([...mappings, { platform: f.platforms[0] ?? "spl", from: "", to: "" }])}>Add mapping</Button>
            </div>
          </div>
        </section>

        <section className="space-y-5 rounded-md border border-line bg-surface p-6">
          <h3 className="text-h3 font-semibold">Reports</h3>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Default TLP" htmlFor="w-tlp"><Select id="w-tlp" value={f.default_tlp} onChange={(v) => setF({ ...f, default_tlp: v })} options={TLPS.map((t) => ({ value: t, label: `TLP:${t}` }))} /></Field>
          </div>
          <Field label="Disclaimer" optional htmlFor="w-disc"><Textarea id="w-disc" className="min-h-[70px]" value={f.branding.disclaimer ?? ""} onChange={(e) => setF({ ...f, branding: { ...f.branding, disclaimer: e.target.value } })} /></Field>
          {!isNew && (
            <div>
              <div className="mb-1.5 text-[13px] font-semibold">Logo</div>
              <div className="flex items-center gap-3">
                <input ref={fileRef} type="file" accept="image/png,image/jpeg" className="hidden" onChange={(e) => e.target.files?.[0] && uploadLogo(e.target.files[0])} />
                <Button icon={<Upload />} onClick={() => fileRef.current?.click()}>{existing?.branding.has_logo ? "Replace logo" : "Upload logo"}</Button>
                <span className="text-caption text-fg-muted">PNG or JPEG under 200 KB. Inlined as base64 in email exports.</span>
              </div>
            </div>
          )}
        </section>
      </div>
      <div className="fixed right-0 bottom-0 left-0 z-[150] border-t border-line bg-surface sm:left-16 lg:left-[var(--sb,240px)]">
        <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-end gap-3 px-4 md:px-6">
          <Button onClick={() => router.push("/settings/workspaces")}>Cancel</Button>
          <Button variant="primary" size="lg" loading={saving} onClick={save}>Save workspace</Button>
        </div>
      </div>
    </Page>
  );
}
