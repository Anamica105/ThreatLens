"use client";

import { useState } from "react";
import { useApp } from "@/components/providers";
import { Pill } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Alert, SkeletonRows, useToast } from "@/components/ui/feedback";
import { Field, Input } from "@/components/ui/forms";
import { Page, PageHeader, Panel } from "@/components/ui/layout";
import { IOC_TYPE_LABEL } from "@/lib/constants";
import { put } from "@/lib/api";
import { useApi } from "@/lib/hooks";

interface K { id: string; name: string; types: string[]; configured: boolean; source: string | null; hint: string }
interface Expiry { days: Record<string, number | null>; defaults: Record<string, number | null>; note: string }

/** Expiry age per IoC type (PUT /api/settings/ioc-expiry). Empty = never expires. */
function ExpirySettings({ canEdit }: { canEdit: boolean }) {
  const toast = useToast();
  const { data, error, setData } = useApi<Expiry>("/api/settings/ioc-expiry");
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  if (error) return <Alert tone="danger" title="IoC expiry unavailable">{error.message}</Alert>;
  if (!data) return <SkeletonRows rows={3} />;
  const val = (t: string) => draft[t] ?? (data.days[t] == null ? "" : String(data.days[t]));
  const bad = Object.values(draft).some((v) => v !== "" && !(/^\d+$/.test(v) && +v >= 1 && +v <= 3650));
  const dirty = Object.keys(draft).some((t) => draft[t] !== (data.days[t] == null ? "" : String(data.days[t])));
  const save = async () => {
    setSaving(true);
    try {
      setData(await put<Expiry>("/api/settings/ioc-expiry", { days: Object.fromEntries(Object.entries(draft).map(([t, v]) => [t, v === "" ? null : +v])) }));
      setDraft({});
      toast({ tone: "success", message: "IoC expiry saved. It applies to the next run or enrichment; library expiry dates were recalculated." });
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setSaving(false); }
  };
  return (
    <Panel title="IoC expiry">
      <p className="mb-4 text-body-sm text-fg-muted">
        Infrastructure older than this is marked <strong>Expired</strong> and left out of retro-hunts unless the hunter opts in on the research IoCs tab.
        Age is counted from the indicator&apos;s intel first-seen: the earliest source publication date or OSINT first-seen, not when ThreatLens stored it. Leave empty for never.
      </p>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Object.keys(data.days).map((t) => (
          <Field key={t} label={IOC_TYPE_LABEL[t] ?? t} htmlFor={`exp-${t}`} help={`Default: ${data.defaults[t] == null ? "never" : `${data.defaults[t]} days`}`}>
            <Input id={`exp-${t}`} inputMode="numeric" disabled={!canEdit} placeholder="Never" suffix="days" value={val(t)}
              invalid={draft[t] !== undefined && draft[t] !== "" && !(/^\d+$/.test(draft[t]) && +draft[t] >= 1 && +draft[t] <= 3650)}
              onChange={(e) => setDraft({ ...draft, [t]: e.target.value.trim() })} />
          </Field>
        ))}
      </div>
      <div className="mt-4 flex justify-end gap-2">
        {dirty && <Button onClick={() => setDraft({})}>Discard</Button>}
        <Button variant="primary" loading={saving} disabled={!canEdit || !dirty || bad} disabledReason={bad ? "Use 1 to 3650 days, or leave empty for never" : "Change an age first"} onClick={save}>Save expiry</Button>
      </div>
    </Panel>
  );
}

export default function OsintKeys() {
  const { user } = useApp();
  const toast = useToast();
  const { data, setData } = useApi<K[]>("/api/settings/osint-keys");
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const canEdit = user?.role === "lead" || user?.role === "admin";
  const save = async (extra?: Record<string, null>) => {
    setSaving(true);
    try {
      setData(await put<K[]>("/api/settings/osint-keys", { keys: { ...draft, ...extra } }));
      setDraft({});
      toast({ tone: "success", message: "OSINT keys saved" });
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setSaving(false); }
  };
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Settings", href: "/settings" }, { label: "OSINT API keys" }]} title="OSINT API keys"
        description="Only public indicators are sent to these services; client names never are. Results are cached for 24 hours." />
      <div className="max-w-form space-y-4">
        {!canEdit && <Alert tone="info" title="Read only">Only leads and admins can change keys. Switch user from the account menu to try it.</Alert>}
        <Alert tone="warning" title="Storage">Keys entered here are stored in the application database. In production, keep them in a secrets vault and supply them as environment variables to the API.</Alert>
        {!data ? <SkeletonRows rows={7} /> : (
          <div className="divide-y divide-[var(--border-subtle)] rounded-md border border-line bg-surface">
            {data.map((k) => (
              <div key={k.id} className="flex flex-wrap items-center gap-3 p-4">
                <div className="min-w-[200px] flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-h4 font-semibold">{k.name}</span>
                    {k.configured ? <Pill tone="success">Configured</Pill> : <Pill tone="neutral">Not set</Pill>}
                  </div>
                  <div className="text-caption text-fg-muted">{k.types.join(", ")}{k.source ? ` · from ${k.source}` : ""}{k.hint ? ` · ${k.hint}` : ""}</div>
                </div>
                <Input type="password" autoComplete="off" className="w-full sm:w-72" placeholder={k.configured ? "Enter a new key to replace" : "API key"} aria-label={`${k.name} API key`}
                  disabled={!canEdit} value={draft[k.id] ?? ""} onChange={(e) => setDraft({ ...draft, [k.id]: e.target.value })} />
                {k.source === "settings" && canEdit && <Button size="sm" variant="danger-secondary" onClick={() => save({ [k.id]: null })}>Remove</Button>}
              </div>
            ))}
          </div>
        )}
        <div className="flex justify-end"><Button variant="primary" loading={saving} disabled={!canEdit || !Object.values(draft).some(Boolean)} disabledReason="Enter at least one key" onClick={() => save()}>Save keys</Button></div>
        <ExpirySettings canEdit={canEdit} />
      </div>
    </Page>
  );
}
