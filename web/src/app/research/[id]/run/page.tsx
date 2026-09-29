"use client";

import clsx from "clsx";
import { ArrowDown, CircleCheck, CircleX, ExternalLink, RotateCcw, Square, TriangleAlert } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { useWsHref } from "@/components/providers";
import { Badge, Pill, SourceRating } from "@/components/ui/badges";
import { Button, ButtonLink } from "@/components/ui/button";
import { Alert, ErrorState, ProgressBar, Skeleton, useToast } from "@/components/ui/feedback";
import { Toggle } from "@/components/ui/forms";
import { Page, PageHeader, Panel } from "@/components/ui/layout";
import { get, post } from "@/lib/api";
import { duration, elapsed, toDate, utc } from "@/lib/format";
import type { ResearchDetail, RunDetail, RunLog, RunStage } from "@/lib/types";
import { BudgetMeter, type RunBudget } from "./budget";

type RunWithBudget = RunDetail & { budget?: RunBudget };

function StageIcon({ state }: { state: RunStage["state"] }) {
  if (state === "done") return <CircleCheck className="size-5 text-success" />;
  if (state === "warning") return <TriangleAlert className="size-5" style={{ color: "var(--warning)" }} />;
  if (state === "failed") return <CircleX className="size-5 text-danger" />;
  if (state === "running")
    return (
      <svg className="spin size-5" viewBox="0 0 20 20" aria-hidden>
        <circle cx="10" cy="10" r="8" fill="none" stroke="var(--accent-soft-2)" strokeWidth="2" />
        <path d="M10 2a8 8 0 0 1 8 8" fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  return <span className="block size-5 rounded-full border-2 border-[var(--g-300)]" />;
}

export default function RunProgress() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const wsHref = useWsHref();
  const toast = useToast();
  const [runId, setRunId] = useState<string | null>(null);
  const [run, setRun] = useState<RunWithBudget | null>(null);
  const [logs, setLogs] = useState<RunLog[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [filter, setFilter] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [follow, setFollow] = useState(true);
  const [, tick] = useState(0);
  const lastLog = useRef(0);
  const logBox = useRef<HTMLDivElement | null>(null);
  const notified = useRef(false);

  useEffect(() => {
    get<ResearchDetail>(`/api/research/${id}`).then((r) => {
      if (r.run) setRunId(r.run.id);
      else setError(new Error("This research has no pipeline run."));
    }).catch(setError);
  }, [id]);

  const inFlight = useRef(false);
  const poll = useCallback(async () => {
    if (!runId || inFlight.current) return;
    inFlight.current = true;
    try {
      const r = await get<RunWithBudget>(`/api/runs/${runId}?after_log=${lastLog.current}`);
      setRun(r);
      if (r.logs.length) {
        lastLog.current = Math.max(lastLog.current, r.logs[r.logs.length - 1].id);
        setLogs((xs) => {
          const seen = new Set(xs.map((x) => x.id));
          return [...xs, ...r.logs.filter((l) => !seen.has(l.id))].slice(-2000);
        });
      }
      if (r.status === "done" && !r.active && !notified.current) {
        notified.current = true;
        toast({ tone: "success", message: `Run completed · draft ${id} is ready for review`, action: { label: "View", onClick: () => router.push(wsHref(`/research/${id}`)) } });
        setTimeout(() => router.push(wsHref(`/research/${id}?done=1`)), 1500);
      }
    } catch (e) {
      setError(e as Error);
    } finally {
      inFlight.current = false;
    }
  }, [runId, id, router, toast, wsHref]);

  useEffect(() => {
    if (!runId) return;
    poll();
    const t = setInterval(() => { poll(); tick((n) => n + 1); }, 1500);
    return () => clearInterval(t);
  }, [runId, poll]);

  useEffect(() => {
    if (follow && logBox.current) logBox.current.scrollTop = logBox.current.scrollHeight;
  }, [logs, follow, filter]);

  if (error) return <Page><ErrorState error={error} /></Page>;
  const done = run?.stages.filter((s) => s.state === "done" || s.state === "warning").length ?? 0;
  const running = run && (run.active || run.status === "running" || run.status === "queued");
  const failed = run?.stages.find((s) => s.state === "failed");
  const total = run ? (toDate(run.finished_at) ?? new Date()).getTime() - (toDate(run.started_at) ?? new Date()).getTime() : 0;
  const shownLogs = logs.filter((l) => l.level !== "debug" && (!filter || l.stage === filter));

  const retry = async (stage: string) => {
    try {
      await post(`/api/runs/${runId}/retry`, { stage });
      notified.current = false;
      toast({ tone: "info", message: "Stage retried" });
      poll();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };
  const cancel = async () => {
    try { await post(`/api/runs/${runId}/cancel`); toast({ tone: "info", message: "Run cancelled" }); poll(); }
    catch (e) { toast({ tone: "danger", message: (e as Error).message }); }
  };
  const exclude = async (sid: string, excluded: boolean) => {
    await post(`/api/runs/${runId}/sources/${sid}`, { excluded });
    poll();
  };

  return (
    <Page>
      <PageHeader crumbs={[{ label: "Research", href: "/research" }, { label: id, href: `/research/${id}`, mono: true }, { label: "Run" }]}
        title={run?.title || "Research run"}
        description={run ? <>
          <span className="tabular">{done} of {run.stages.length} stages</span> · elapsed <span className="tabular">{duration(total / 1000)}</span>
          {run.mode === "offline" && " · offline mode"}{run.tokens ? ` · ${run.tokens.toLocaleString()} tokens` : ""}
        </> : "Loading…"}
        actions={<>
          {running && <Button variant="danger-secondary" icon={<Square />} onClick={cancel}>Cancel run</Button>}
          <ButtonLink href={wsHref(`/research/${id}`)} variant={running ? "secondary" : "primary"}>Open research</ButtonLink>
        </>}>
        {run && <div className="mt-4 max-w-xl"><ProgressBar value={done} max={run.stages.length} label={running ? `Running · ${done} of ${run.stages.length} stages` : run.status === "done" ? "Complete" : run.status === "cancelled" ? "Cancelled" : failed ? `Stopped at ${failed.label}` : run.status} /></div>}
        {run?.budget && <BudgetMeter budget={run.budget} running={!!running} />}
      </PageHeader>

      {failed && failed.message && (
        <Alert tone="danger" className="mb-6" title={`${failed.label} failed`} action={<Button size="sm" icon={<RotateCcw />} onClick={() => retry(failed.id)}>Retry stage</Button>}>
          {failed.message}
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-[minmax(320px,420px)_1fr]">
        <Panel title="Pipeline" bodyClassName="!pt-2">
          {!run ? <div className="space-y-4">{Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-5 w-4/5" />)}</div> : (
            <ol aria-live="polite" aria-label="Pipeline stages">
              {run.stages.map((s, i) => (
                <li key={s.id} className="relative flex gap-3 pb-1">
                  {i < run.stages.length - 1 && <span className="absolute top-7 bottom-0 left-[9.5px] w-px bg-[var(--g-200)] dark:bg-[var(--g-700)]" aria-hidden />}
                  <span className="relative mt-2 bg-surface"><StageIcon state={s.state} /></span>
                  <div className="min-w-0 flex-1 rounded-sm px-2 py-2 hover:bg-subtle">
                    <button className="flex w-full items-center gap-2 text-left" onClick={() => { setExpanded(expanded === s.id ? null : s.id); setFilter(s.id); }} aria-expanded={expanded === s.id}>
                      <span className={clsx("flex-1 truncate text-[14px]", s.state === "running" ? "font-semibold text-fg" : s.state === "pending" ? "text-fg-muted" : "text-fg")}>{s.label}</span>
                      {(s.started_at && s.state !== "pending") && <span className="tabular text-caption text-fg-muted">{elapsed(s.started_at, s.finished_at)}</span>}
                      {s.badge && <Badge>{s.badge}</Badge>}
                    </button>
                    {s.message && s.state !== "failed" && <p className="mt-1 text-body-sm" style={{ color: s.state === "warning" ? "var(--warning)" : undefined }}>{s.message}</p>}
                    {s.state === "failed" && (
                      <div className="mt-1">
                        <p className="text-body-sm text-danger">{s.message}</p>
                        <Button size="sm" className="mt-2" icon={<RotateCcw />} onClick={() => retry(s.id)}>Retry stage</Button>
                      </div>
                    )}
                    {expanded === s.id && (
                      <div className="mt-2 max-h-40 overflow-y-auto rounded-sm bg-code p-2 font-mono text-mono-sm">
                        {logs.filter((l) => l.stage === s.id && l.level !== "debug").map((l) => <div key={l.id} className={l.level === "error" ? "text-danger" : l.level === "warn" ? "text-warning" : "text-fg-strong"}>{l.message}</div>)}
                        {!logs.some((l) => l.stage === s.id) && <span className="text-fg-muted">No log lines yet</span>}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Panel>

        <div className="min-w-0 space-y-6">
          <Panel title="Live log" actions={
            <div className="flex flex-wrap gap-1">
              <button onClick={() => setFilter(null)} className={clsx("h-7 rounded-sm px-2 text-[13px] font-semibold", !filter ? "bg-accent-soft text-accent-text" : "text-fg-muted hover:bg-subtle")}>All</button>
              {run?.stages.filter((s) => logs.some((l) => l.stage === s.id)).map((s) => (
                <button key={s.id} onClick={() => setFilter(s.id)} className={clsx("h-7 rounded-sm px-2 text-[13px] font-semibold", filter === s.id ? "bg-accent-soft text-accent-text" : "text-fg-muted hover:bg-subtle")}>{s.label.split(" ")[0]}</button>
              ))}
            </div>
          }>
            <div className="relative">
              <div ref={logBox} role="log" aria-live="off" onScroll={(e) => { const el = e.currentTarget; setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24); }}
                className="h-[420px] overflow-y-auto rounded-sm bg-code p-3 font-mono text-mono-sm leading-5">
                {shownLogs.map((l) => (
                  <div key={l.id} className="flex gap-3">
                    <span className="shrink-0 text-fg-faint" title={utc(l.created_at)}>{toDate(l.created_at)?.toISOString().slice(11, 19)}</span>
                    <span className="w-20 shrink-0 truncate text-fg-muted">{l.stage}</span>
                    <span className={clsx("min-w-0 break-words", l.level === "error" ? "text-danger" : l.level === "warn" ? "text-[var(--warning)]" : "text-fg")}>{l.message}</span>
                  </div>
                ))}
                {!shownLogs.length && <span className="text-fg-muted">Waiting for the first log line…</span>}
              </div>
              {!follow && (
                <button onClick={() => { setFollow(true); if (logBox.current) logBox.current.scrollTop = logBox.current.scrollHeight; }}
                  className="absolute right-3 bottom-3 inline-flex h-7 items-center gap-1 rounded-full border border-line bg-raised px-3 text-[13px] font-semibold shadow-elev-2">
                  <ArrowDown className="size-4" /> Jump to latest
                </button>
              )}
            </div>
          </Panel>

          <Panel title={`Sources${run?.sources.length ? ` · ${run.sources.length}` : ""}`}>
            {!run?.sources.length ? <p className="text-fg-muted">Sources appear here after discovery.</p> : (
              <ul className="divide-y divide-[var(--border-subtle)]">
                {run.sources.map((s) => (
                  <li key={s.id} className="flex items-center gap-3 py-2.5">
                    <span className="w-7 font-mono text-mono-sm text-fg-muted">{s.id}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[14px] font-semibold">{s.publisher}</span>
                        <SourceRating reliability={s.reliability || "C"} credibility={s.reliability === "A" || s.reliability === "B" ? 2 : 3} />
                      </div>
                      {s.url ? <a href={s.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 truncate text-body-sm text-accent-text hover:underline"><span className="truncate">{s.title}</span><ExternalLink className="size-3 shrink-0" /></a>
                        : <span className="text-body-sm text-fg-muted">{s.title}</span>}
                    </div>
                    <Pill tone={s.state === "read" ? "success" : s.state === "failed" ? "danger" : s.state === "excluded" ? "muted" : "neutral"} running={s.state === "pending" && !!running}>
                      {s.state === "read" ? "Read" : s.state === "failed" ? "Unreadable" : s.state === "excluded" ? "Excluded" : "Pending"}
                    </Pill>
                    {running && <Toggle checked={!s.excluded} onChange={(v) => exclude(s.id, !v)} label={<span className="sr-only">Include {s.id}</span>} />}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </Page>
  );
}
