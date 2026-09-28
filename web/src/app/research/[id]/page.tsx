"use client";

import { Archive, ChevronDown, Copy, Download, FileJson, FileSpreadsheet, FileText, Mail, Presentation, RotateCcw, Send, Upload, Undo2 } from "lucide-react";
import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApp, useWsHref } from "@/components/providers";
import { pushRecent } from "@/components/shell/command-palette";
import { TacticRail } from "@/components/research/tactic-rail";
import { ActivityTab, SourcesTab } from "@/components/research/detail/sources-activity";
import { HuntsTab } from "@/components/research/detail/hunts-tab";
import { IocsTab } from "@/components/research/detail/iocs-tab";
import { ListTab } from "@/components/research/detail/list-tab";
import { ReportTab } from "@/components/research/detail/report-tab";
import { StudyTab } from "@/components/research/detail/study-tab";
import { TreeTab } from "@/components/research/detail/tree-tab";
import { PathTab } from "@/components/research/detail/path-tab";
import { groupQueries } from "@/components/research/provenance";
import { Chip, ConfidenceBadge, ResultPill, SeverityBadge, StatusPill, TlpBadge } from "@/components/ui/badges";
import { Button, ButtonGroup, ButtonLink } from "@/components/ui/button";
import { Banner, EmptyState, ErrorState, Skeleton, useToast } from "@/components/ui/feedback";
import { Checkbox, Field, MultiSelect, Select } from "@/components/ui/forms";
import { Breadcrumbs, Page, Tabs } from "@/components/ui/layout";
import { Dialog, Menu } from "@/components/ui/overlay";
import { download, fetchText, patch, post } from "@/lib/api";
import { CLASSIFICATION, SEVERITY } from "@/lib/constants";
import { copyText, useApi, useLocalStorage } from "@/lib/hooks";
import type { ResearchDetail } from "@/lib/types";
import { FileX } from "lucide-react";

const TABS = ["report", "path", "tree", "list", "study", "hunts", "iocs", "sources", "activity"] as const;
type Tab = (typeof TABS)[number];

const EXPORTS = [
  { id: "pdf", label: "PDF", icon: <FileText /> },
  { id: "email", label: "Email (HTML)", icon: <Mail /> },
  { id: "pptx", label: "2-slide PPT", icon: <Presentation /> },
  { id: "json", label: "JSON", icon: <FileJson /> },
  { id: "iocs_csv", label: "IoCs CSV", icon: <FileSpreadsheet /> },
  { id: "queries_csv", label: "Queries CSV", icon: <FileSpreadsheet /> },
] as const;

export default function ResearchDetailPage() {
  const { id } = useParams<{ id: string }>();
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const { ws, user, workspaces, wsName, activeWorkspace } = useApp();
  const wsHref = useWsHref();
  const toast = useToast();
  const { data: d, error, reload: rawReload } = useApi<ResearchDetail>(`/api/research/${id}${ws !== "all" ? `?ws=${ws}` : ""}`);
  const reload = useCallback(async () => { await rawReload(); }, [rawReload]);
  const tab = (TABS.includes(params.get("tab") as Tab) ? params.get("tab") : "report") as Tab;
  const [tacticFilter, setTacticFilter] = useState<string | null>(null);
  const [lastExport, setLastExport] = useLocalStorage<string>("tl.lastExport", "pdf");
  const [exporting, setExporting] = useState(false);
  const [emailOpen, setEmailOpen] = useState(false);
  const [exportOpts, setExportOpts] = useState(false);
  const [rerunOpen, setRerunOpen] = useState(params.get("rerun") === "1");
  const [confirm, setConfirm] = useState<null | "archive">(null);
  const [compact, setCompact] = useState(false);
  const animate = params.get("done") === "1";
  const headerRef = useRef<HTMLDivElement | null>(null);

  const setTab = useCallback((t: string) => {
    const p = new URLSearchParams(params.toString());
    p.set("tab", t);
    p.delete("done");
    router.replace(`${pathname}?${p.toString()}`, { scroll: false });
  }, [params, pathname, router]);

  useEffect(() => { if (d) pushRecent(d.title, `/research/${d.id}`); }, [d]);
  useEffect(() => {
    const onScroll = () => setCompact(window.scrollY > 120);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable || e.ctrlKey || e.metaKey || e.altKey) return;
      const n = Number(e.key);
      if (n >= 1 && n <= TABS.length) setTab(TABS[n - 1]);
      if (e.key === "c") {
        const el = document.activeElement?.closest("[data-copy]") as HTMLElement | null;
        if (el?.dataset.copy) { copyText(el.dataset.copy); toast({ tone: "success", message: "Copied" }); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [setTab, toast]);

  const patchRecord = useCallback(async (changes: Record<string, unknown>, summary?: string) => {
    try {
      await patch(`/api/research/${id}/record`, { changes, summary });
      toast({ tone: "success", message: "Saved" });
      await reload();
    } catch (e) {
      toast({ tone: "danger", message: (e as Error).message });
      throw e;
    }
  }, [id, reload, toast]);

  if (error) {
    if ((error as { status?: number }).status === 404)
      return <Page><EmptyState icon={<FileX />} title="This page doesn't exist" body="The research may have been archived or the link is wrong." action={<ButtonLink href={wsHref("/research")} variant="primary">Go to Research</ButtonLink>} /></Page>;
    return <Page><ErrorState error={error} onRetry={reload} /></Page>;
  }
  if (!d) return <Page><div className="space-y-4 pt-8"><Skeleton className="h-3 w-40" /><Skeleton className="h-8 w-3/5" /><Skeleton className="h-4 w-2/5" /><Skeleton className="mt-6 h-2.5 w-full" /><Skeleton className="mt-8 h-64 w-full" /></div></Page>;

  const rec = d.record;
  if (!rec || !rec.title) {
    return (
      <Page>
        <div className="pt-6"><Breadcrumbs items={[{ label: "Research", href: "/research" }, { label: d.id, mono: true }]} /></div>
        <EmptyState icon={<FileX />} title={d.status === "running" ? "The run is still in progress" : d.status === "failed" ? "The run failed before producing a report" : "This draft has not been run yet"}
          body={d.seed.slice(0, 200)}
          action={d.status === "draft" && !d.run?.active ? <Button variant="primary" onClick={async () => { await post(`/api/research/${d.id}/start`); router.push(wsHref(`/research/${d.id}/run`)); }}>Start research</Button>
            : <ButtonLink href={wsHref(`/research/${d.id}/run`)} variant="primary">Open run progress</ButtonLink>} />
      </Page>
    );
  }

  const canEdit = d.status !== "archived";
  const isReviewer = !!user && ["reviewer", "lead", "admin"].includes(user.role);
  const sev = SEVERITY[d.severity] ?? SEVERITY.medium;
  const curResult = ws !== "all" ? d.results.find((r) => r.workspace_id === ws) : null;
  const counts = { hunts: rec.hunts?.queries?.length ? groupQueries(rec).length : 0, iocs: rec.iocs.length, sources: rec.sources.length };

  const doExport = async (fmt: string, opts?: { hide?: string[]; study?: boolean }) => {
    if (fmt === "email") { setEmailOpen(true); setLastExport("email"); return; }
    setExporting(true);
    try {
      const qp = new URLSearchParams();
      if (ws !== "all") qp.set("ws", ws);
      opts?.hide?.forEach((h) => qp.append("hide", h));
      if (opts?.study) qp.set("study", "true");
      const name = await download(`/api/research/${d.id}/export/${fmt}?${qp}`);
      setLastExport(fmt);
      toast({ tone: "success", message: `Exported ${d.id} as ${EXPORTS.find((e) => e.id === fmt)?.label ?? fmt}` });
      void name;
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setExporting(false); }
  };

  const status = async (action: string) => {
    try {
      await post(`/api/research/${d.id}/status`, { action });
      toast({ tone: "success", message: { submit: "Review requested", publish: "Published", archive: "Archived", restore: "Restored", reopen: "Reopened" }[action] ?? "Updated" });
      setConfirm(null);
      reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };

  const last = EXPORTS.find((e) => e.id === lastExport) ?? EXPORTS[0];
  const primary = d.status === "draft" || d.status === "failed" ? { label: "Submit for review", icon: <Send />, run: () => status("submit") }
    : d.status === "in_review" ? (isReviewer ? { label: "Publish", icon: <Upload />, run: () => status("publish") } : null)
    : d.status === "archived" ? { label: "Restore", icon: <Undo2 />, run: () => status("restore") } : null;

  const tabs = [
    { id: "report", label: "Report" }, { id: "path", label: "Research path" }, { id: "tree", label: "Tree" }, { id: "list", label: "List" }, { id: "study", label: "Study" },
    { id: "hunts", label: "Hunts", count: counts.hunts }, { id: "iocs", label: "IoCs", count: counts.iocs }, { id: "sources", label: "Sources", count: counts.sources },
    { id: "activity", label: "Activity" },
  ];
  const props = { d, reload, patchRecord, canEdit, ws };

  return (
    <div>
      {d.tlp === "RED" && <Banner tone="danger">This report is <TlpBadge tlp="RED" /> — email export is disabled.</Banner>}
      {d.status === "running" && <Banner tone="info" action={<ButtonLink size="sm" href={wsHref(`/research/${d.id}/run`)}>View run</ButtonLink>}>A pipeline run is updating this research.</Banner>}
      <Page>
        <div className="pt-6 pb-2"><Breadcrumbs items={[{ label: "Research", href: "/research" }, { label: d.id, mono: true }]} /></div>
        <div ref={headerRef} className="relative flex overflow-hidden rounded-md border border-line bg-surface">
          <span className="w-1 shrink-0" style={{ background: sev.solid }} aria-hidden />
          <span className="sr-only">Severity: {sev.label}</span>
          <div className="min-w-0 flex-1 space-y-4 p-5">
            <h1 className="text-display font-bold tracking-[-0.005em] break-words [overflow-wrap:anywhere]">{rec.title}</h1>
            <div className="flex flex-wrap items-center gap-2">
              <StatusPill status={d.status} />
              <SeverityBadge severity={d.severity} />
              <TlpBadge tlp={d.tlp} />
              <ConfidenceBadge level={d.confidence} />
              <span className="mx-1 h-5 w-px bg-[var(--border-default)]" aria-hidden />
              {d.cves.slice(0, 1).map((c) => <Chip key={c} dot={CLASSIFICATION.cve.color} mono href={wsHref(`/research?cve=${c}`)}>{c}</Chip>)}
              {d.cves.length > 1 && <Chip title={d.cves.slice(1).join(", ")}>+{d.cves.length - 1}</Chip>}
              {d.actors.slice(0, 1).map((a) => <Chip key={a} dot={CLASSIFICATION.actor.color} href={wsHref(`/library/actors/${a.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`)}>{a}</Chip>)}
              {d.actors.length > 1 && <Chip title={d.actors.slice(1).join(", ")}>+{d.actors.length - 1}</Chip>}
            </div>
            <TacticRail tactics={d.rail} onSelect={(t) => { setTacticFilter(t); if (t && tab !== "report" && tab !== "list") setTab("report"); if (t) setTimeout(() => document.getElementById("mitre")?.scrollIntoView({ behavior: "smooth" }), 50); }} selected={tacticFilter} animate={animate} />
            <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
              {activeWorkspace ? (
                <span className="flex items-center gap-2 text-[14px]">
                  <span className="font-semibold">{activeWorkspace.name}:</span>
                  {curResult ? <ResultPill status={curResult.status} suffix={curResult.hunt_window ? `hunted ${curResult.hunt_window.split("–").pop()?.trim()}` : undefined} /> : <span className="text-fg-muted">not in scope</span>}
                </span>
              ) : (
                <span className="flex flex-wrap items-center gap-2 text-[14px]">
                  {d.results.map((r) => <span key={r.workspace_id} className="flex items-center gap-1.5"><span className="text-fg-muted">{wsName(r.workspace_id)}</span><ResultPill status={r.status} /></span>)}
                </span>
              )}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                <Button icon={<RotateCcw />} onClick={() => setRerunOpen(true)} disabled={!!d.run?.active}>Re-run</Button>
                <Button icon={<Mail />} onClick={() => doExport("email")} disabled={d.tlp === "RED"} disabledReason="TLP:RED reports cannot be emailed">Email</Button>
                <ButtonGroup>
                  <Button icon={last.icon} loading={exporting} onClick={() => (last.id === "pdf" ? setExportOpts(true) : doExport(last.id))}>Export {last.label}</Button>
                  <Menu width={220} items={[
                    ...EXPORTS.map((e) => ({ label: e.label, icon: e.icon, onSelect: () => (e.id === "pdf" ? setExportOpts(true) : doExport(e.id)), disabled: e.id === "email" && d.tlp === "RED" })),
                    { label: "", divider: true, onSelect: () => undefined },
                    { label: "Archive", icon: <Archive />, danger: true, onSelect: () => setConfirm("archive"), disabled: d.status === "archived" },
                  ]} trigger={(p) => <Button {...p} aria-label="More export formats" className="!px-2"><ChevronDown /></Button>} />
                </ButtonGroup>
                {primary && <Button variant="primary" icon={primary.icon} onClick={primary.run}>{primary.label}</Button>}
                {d.status === "in_review" && !isReviewer && <span className="text-caption text-fg-muted">Awaiting reviewer</span>}
              </div>
            </div>
          </div>
        </div>

        {compact && (
          <div className="fixed top-14 right-0 left-0 z-[100] border-b border-line bg-surface shadow-elev-1 sm:left-16 lg:left-[var(--sb,240px)]">
            <div className="mx-auto flex h-12 max-w-[1440px] items-center gap-3 px-4 md:px-6">
              <span className="h-6 w-1 rounded-full" style={{ background: sev.solid }} />
              <span className="min-w-0 flex-1 truncate text-h3 font-semibold">{rec.title}</span>
              <StatusPill status={d.status} />
              {primary && <Button size="sm" variant="primary" onClick={primary.run}>{primary.label}</Button>}
            </div>
          </div>
        )}

        <div className="sticky top-14 z-[90] mt-6 bg-app pt-1" style={{ top: compact ? 104 : 56 }}>
          <Tabs ariaLabel="Research sections" tabs={tabs} value={tab} onChange={setTab} />
        </div>
        <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} className="pt-6">
          {tab === "report" && <ReportTab {...props} tacticFilter={tacticFilter} />}
          {tab === "path" && <PathTab {...props} />}
          {tab === "tree" && <TreeTab {...props} />}
          {tab === "list" && <ListTab {...props} tacticFilter={tacticFilter} />}
          {tab === "study" && <StudyTab {...props} />}
          {tab === "hunts" && <HuntsTab {...props} />}
          {tab === "iocs" && <IocsTab {...props} />}
          {tab === "sources" && <SourcesTab {...props} />}
          {tab === "activity" && <ActivityTab {...props} />}
        </div>
      </Page>

      <EmailDialog open={emailOpen} onClose={() => setEmailOpen(false)} d={d} ws={ws} workspaces={workspaces.map((w) => ({ id: w.id, name: w.name }))} />
      <PdfOptions open={exportOpts} onClose={() => setExportOpts(false)} onExport={(hide, study) => { setExportOpts(false); doExport("pdf", { hide, study }); }} />
      <RerunDialog open={rerunOpen} onClose={() => setRerunOpen(false)} d={d} onDone={(runId) => { void runId; router.push(wsHref(`/research/${d.id}/run`)); }} />
      <Dialog open={confirm === "archive"} onClose={() => setConfirm(null)} size="sm" title={`Archive ${d.id}?`}
        footer={<><Button onClick={() => setConfirm(null)}>Cancel</Button><Button variant="danger" onClick={() => status("archive")}>Archive</Button></>}>
        <p>Archived research leaves the library and dashboards and becomes read-only. You can restore it later.</p>
      </Dialog>
    </div>
  );
}

function PdfOptions({ open, onClose, onExport }: { open: boolean; onClose: () => void; onExport: (hide: string[], study: boolean) => void }) {
  const [iocs, setIocs] = useState(true);
  const [queries, setQueries] = useState(true);
  const [sources, setSources] = useState(true);
  const [study, setStudy] = useState(false);
  return (
    <Dialog open={open} onClose={onClose} size="md" title="Export PDF" description="A4, TLP marking on every page, appendices at the end."
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" icon={<Download />} onClick={() => onExport([...(iocs ? [] : ["iocs"]), ...(queries ? [] : ["queries"]), ...(sources ? [] : ["sources"])], study)}>Export PDF</Button></>}>
      <fieldset className="space-y-2">
        <legend className="mb-2 text-[13px] font-semibold">Sections</legend>
        <Checkbox checked={iocs} onChange={setIocs} label="Appendix A — IoCs" description="Hide for executive audiences." />
        <Checkbox checked={queries} onChange={setQueries} label="Appendix B — Hunt queries" />
        <Checkbox checked={sources} onChange={setSources} label="Appendix C — Sources" />
        <Checkbox checked={study} onChange={setStudy} label="Study notes" />
      </fieldset>
    </Dialog>
  );
}

function EmailDialog({ open, onClose, d, ws, workspaces }: { open: boolean; onClose: () => void; d: ResearchDetail; ws: string; workspaces: { id: string; name: string }[] }) {
  const [target, setTarget] = useState(ws !== "all" ? ws : d.workspace_ids[0] ?? "");
  const [html, setHtml] = useState<string>("");
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  useEffect(() => {
    if (!open) return;
    setErr(null);
    fetchText(`/api/research/${d.id}/export/email?inline=true${target ? `&ws=${target}` : ""}`).then(setHtml).catch((e) => setErr((e as Error).message));
  }, [open, target, d.id]);
  return (
    <Dialog open={open} onClose={onClose} size="lg" title="Email report" description="600 px, inline CSS, no external images. Send it from your mail client."
      footer={<>
        <Button onClick={onClose}>Close</Button>
        <Button icon={<Copy />} disabled={!html} onClick={async () => { await copyText(html); toast({ tone: "success", message: "Email HTML copied" }); }}>Copy HTML</Button>
        <Button variant="primary" icon={<Download />} onClick={async () => {
          try { await download(`/api/research/${d.id}/export/eml${target ? `?ws=${target}` : ""}`); toast({ tone: "success", message: "Outlook draft (.eml) downloaded" }); }
          catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
        }}>Download .eml draft</Button>
      </>}>
      <div className="space-y-4">
        <Field label="Client" htmlFor="email-ws">
          <Select id="email-ws" value={target} onChange={setTarget} options={workspaces.filter((w) => d.workspace_ids.includes(w.id)).map((w) => ({ value: w.id, label: w.name }))} />
        </Field>
        {err ? <p className="text-danger">{err}</p> : (
          <iframe title="Email preview" srcDoc={html} className="h-[480px] w-full rounded-md border border-line bg-white" sandbox="" />
        )}
      </div>
    </Dialog>
  );
}

function RerunDialog({ open, onClose, d, onDone }: { open: boolean; onClose: () => void; d: ResearchDetail; onDone: (runId: string) => void }) {
  const { meta, workspaces } = useApp();
  const [stage, setStage] = useState("synthesis");
  const [platforms, setPlatforms] = useState<string[]>(d.record?.hunts?.platforms ?? []);
  const [wsIds, setWsIds] = useState<string[]>(d.workspace_ids);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const hasArtifacts = d.run && d.run.mode !== "manual";
  const stages = useMemo(() => [
    { value: "intake", label: "Everything (re-discover sources)" }, { value: "extraction", label: "Re-read sources (articles changed)" },
    { value: "synthesis", label: "Synthesis onwards" }, { value: "attack", label: "ATT&CK mapping onwards" },
    { value: "detection", label: "Detection reasoning onwards" }, { value: "queries", label: "Query generation only" }, { value: "iocs", label: "IoC enrichment only" },
  ], []);
  const go = async () => {
    setBusy(true);
    try {
      const r = await post<{ run_id: string; from_stage: string }>(`/api/research/${d.id}/rerun`, { from_stage: stage, platforms, workspace_ids: wsIds });
      toast({ tone: "info", message: r.from_stage === "intake" && stage !== "intake" ? "No stored stage output; starting a full run" : "Re-run started" });
      onDone(r.run_id);
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setBusy(false); }
  };
  return (
    <Dialog open={open} onClose={onClose} size="md" title={`Re-run ${d.id}`} description="Re-running keeps earlier stage output, so you don't redo source discovery unless you ask to."
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} icon={<RotateCcw />} onClick={go}>Start re-run</Button></>}>
      <div className="space-y-5">
        {!hasArtifacts && <p className="rounded-sm bg-info-soft px-3 py-2 text-body-sm">This record has no stored stage outputs (it was imported or built by hand), so a re-run starts from intake using its seed and source URLs.</p>}
        <Field label="Re-run from" htmlFor="rr-stage"><Select id="rr-stage" value={stage} onChange={setStage} options={stages} /></Field>
        <Field label="Workspaces" htmlFor="rr-ws"><MultiSelect id="rr-ws" ariaLabel="Workspaces" values={wsIds} onChange={setWsIds} options={workspaces.map((w) => ({ value: w.id, label: w.name, color: w.color }))} /></Field>
        <Field label="Output platforms" htmlFor="rr-pl"><MultiSelect id="rr-pl" ariaLabel="Output platforms" values={platforms} onChange={setPlatforms} options={(meta?.platforms ?? []).map((p) => ({ value: p.id, label: p.name }))} /></Field>
      </div>
    </Dialog>
  );
}
