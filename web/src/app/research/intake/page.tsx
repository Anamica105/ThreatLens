"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { DetectedChips, EmlDropZone, INTAKE_STATUS, IocList, RecentIntake, UrlToggleList, type IntakeItem, type IntakeSummary } from "@/components/intake/intake";
import { useApp, useWsHref } from "@/components/providers";
import { Pill, TlpBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Alert, useToast } from "@/components/ui/feedback";
import { Field, MultiSelect, Textarea } from "@/components/ui/forms";
import { Page, PageHeader, Panel } from "@/components/ui/layout";
import { api, get, post } from "@/lib/api";

interface UploadResult { item: IntakeItem; duplicate: boolean; draft: { id: string; run_id: string } | null }

function IntakePage() {
  const { workspaces, activeWorkspace } = useApp();
  const router = useRouter();
  const params = useSearchParams();
  const wsHref = useWsHref();
  const toast = useToast();

  const [items, setItems] = useState<IntakeSummary[]>([]);
  const [item, setItem] = useState<IntakeItem | null>(null);
  const [duplicate, setDuplicate] = useState(false);
  const [busy, setBusy] = useState<"upload" | "draft" | "dismiss" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [seed, setSeed] = useState("");
  const [included, setIncluded] = useState<Set<string>>(new Set());
  const [wsIds, setWsIds] = useState<string[]>([]);

  const reload = useCallback(() => get<{ items: IntakeSummary[] }>("/api/intake").then((r) => setItems(r.items)).catch(() => undefined), []);
  useEffect(() => { reload(); }, [reload]);

  const load = useCallback((it: IntakeItem, dup = false) => {
    setItem(it);
    setDuplicate(dup);
    setSeed(it.seed);
    setIncluded(new Set(it.urls.filter((u) => u.include).map((u) => u.url)));
    const suggested = it.suggested_workspace?.id;
    setWsIds(suggested ? [suggested] : activeWorkspace ? [activeWorkspace.id] : []);
    setError(null);
  }, [activeWorkspace]);

  const open = useCallback(async (id: string) => {
    try {
      load(await get<IntakeItem>(`/api/intake/${encodeURIComponent(id)}`));
    } catch (e) {
      setError((e as Error).message);
    }
  }, [load]);

  const openParam = params.get("item");
  useEffect(() => { if (openParam) open(openParam); }, [openParam, open]);

  const upload = async (f: File) => {
    setBusy("upload");
    setError(null);
    try {
      const fd = new FormData();
      fd.append("file", f);
      const r = await api<UploadResult>("/api/intake/email?create=false", { method: "POST", body: fd });
      load(r.item, r.duplicate);
      reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const toggle = (url: string) => {
    const next = new Set(included);
    if (next.has(url)) next.delete(url); else next.add(url);
    setIncluded(next);
  };

  const createDraft = async () => {
    if (!item) return;
    if (!wsIds.length) { setError("Pick at least one workspace."); return; }
    if (seed.trim().length < 3) { setError("The seed needs at least 3 characters."); return; }
    setBusy("draft");
    try {
      const urls = item.urls.filter((u) => included.has(u.url)).map((u) => u.url);
      const r = await post<{ id: string }>(`/api/intake/${item.id}/draft`, { workspace_ids: wsIds, seed, seed_urls: urls });
      toast({ tone: "success", message: `Saved ${r.id} as draft from ${item.id}` });
      router.push(wsHref(`/research/${r.id}`));
    } catch (e) {
      setError((e as Error).message);
      setBusy(null);
    }
  };

  const dismiss = async () => {
    if (!item) return;
    setBusy("dismiss");
    try {
      await post(`/api/intake/${item.id}/dismiss`);
      toast({ tone: "success", message: `Dismissed ${item.id}` });
      setItem(null);
      reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const articleCount = useMemo(() => item?.urls.filter((u) => included.has(u.url)).length ?? 0, [item, included]);
  const locked = !!item?.research_id || item?.status === "dismissed";
  const st = item ? INTAKE_STATUS[item.status] ?? INTAKE_STATUS.parsed : null;

  return (
    <Page>
      <PageHeader crumbs={[{ label: "Research", href: "/research" }, { label: "Import email" }]} title="Import email"
        description="Turn a forwarded advisory or newsletter into a draft run. Email content is treated as untrusted text: links are not opened until the run collects them." />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-6">
          <EmlDropZone onFile={upload} busy={busy === "upload"} />
          {error && <Alert tone="danger" title="Could not continue" onDismiss={() => setError(null)}>{error}</Alert>}
          {item && (
            <Panel title={<span className="flex flex-wrap items-center gap-2">{item.original?.subject || item.subject || "(no subject)"}{st && <Pill tone={st.tone}>{st.label}</Pill>}</span>}>
              <div className="space-y-5">
                {duplicate && (
                  <Alert tone="info" title={`Already imported as ${item.id}`}>
                    This email (same Message-ID) was imported before{item.research_id ? ` and drafted as ${item.research_id}` : ""}.
                  </Alert>
                )}
                {item.warnings.map((w) => <Alert key={w} tone="warning">{w}</Alert>)}
                <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-body-sm">
                  <dt className="text-fg-muted">From</dt><dd className="truncate">{item.from_name ? `${item.from_name} <${item.from}>` : item.from}</dd>
                  {item.original && <><dt className="text-fg-muted">Original</dt><dd className="truncate">{item.original.from} · {item.original.date}</dd></>}
                  <dt className="text-fg-muted">Marking</dt><dd>{item.tlp ? <TlpBadge tlp={item.tlp} /> : <span className="text-fg-muted">None found (workspace default applies)</span>}</dd>
                </dl>
                <Field label="Seed" htmlFor="intake-seed" help="Subject and body of the original email. Edit before saving.">
                  <Textarea id="intake-seed" autoGrow maxHeight={360} value={seed} disabled={locked} onChange={(e) => setSeed(e.target.value)} />
                </Field>
                <div>
                  <h3 className="mb-1.5 text-[13px] font-semibold">Detected</h3>
                  <DetectedChips item={item} />
                </div>
                {item.iocs.length > 0 && (
                  <div>
                    <h3 className="mb-1.5 text-[13px] font-semibold">Indicators in the email</h3>
                    <IocList iocs={item.iocs} />
                  </div>
                )}
                <div>
                  <h3 className="mb-1 text-[13px] font-semibold">Links</h3>
                  <p className="mb-2 text-caption text-fg-muted">Checked article links become seed URLs ({articleCount} selected). Defanged links stay indicators.</p>
                  <UrlToggleList urls={item.urls} included={included} onToggle={locked ? () => undefined : toggle} />
                </div>
                <Field label="Workspaces" htmlFor="intake-ws"
                  help={item.suggested_workspace ? `Suggested: ${item.suggested_workspace.name} (${item.suggested_workspace.reason})` : "No routing rule matched this sender."}>
                  <MultiSelect id="intake-ws" ariaLabel="Workspaces" values={wsIds} onChange={setWsIds}
                    options={workspaces.map((w) => ({ value: w.id, label: w.name, hint: w.industry, color: w.color }))} />
                </Field>
                <div className="flex flex-wrap items-center gap-2 border-t border-line pt-4">
                  {item.research_id ? (
                    <Button variant="primary" onClick={() => router.push(wsHref(`/research/${item.research_id}`))}>Open {item.research_id}</Button>
                  ) : (
                    <>
                      <Button variant="primary" onClick={createDraft} loading={busy === "draft"} disabled={locked}>Create draft</Button>
                      <Button onClick={dismiss} loading={busy === "dismiss"} disabled={locked}>Dismiss</Button>
                    </>
                  )}
                  <span className="text-caption text-fg-muted">The draft is saved, not started. Review it and press Start.</span>
                </div>
              </div>
            </Panel>
          )}
        </div>
        <Panel title="Recent emails" className="self-start">
          <RecentIntake items={items} onOpen={open} wsHref={wsHref} activeId={item?.id} />
        </Panel>
      </div>
    </Page>
  );
}

export default function Page_() {
  return <Suspense><IntakePage /></Suspense>;
}
