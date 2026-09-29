"use client";

import { Pencil } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { SeenIn } from "@/components/library";
import { useWsHref } from "@/components/providers";
import { TacticRail } from "@/components/research/tactic-rail";
import { SourceTrail } from "@/components/research/provenance";
import { AttackChip, Badge, Chip } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { ErrorState, Skeleton, useToast } from "@/components/ui/feedback";
import { Field, Input, Textarea } from "@/components/ui/forms";
import { DefinitionList, Page, PageHeader, Panel } from "@/components/ui/layout";
import { Dialog } from "@/components/ui/overlay";
import { patch } from "@/lib/api";
import { utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { ProvenanceItem, ResearchStatus, Severity, Tactic } from "@/lib/types";

interface Actor {
  id: string; name: string; aliases: string[]; origin: string; motivation: string[]; target_industries: string[]; target_regions: string[];
  description: string; first_seen: string | null; last_seen: string | null; research_count: number; rail: Tactic[];
  techniques: { id: string; name: string; tactic_ids: string[]; count: number }[]; tools: { id: string; name: string; type: string; count: number }[];
  seen_in: { id: string; title: string; severity: Severity; status: ResearchStatus; created_at: string }[];
  provenance?: ProvenanceItem[]; provenance_total?: number;
}

export default function ActorProfile() {
  const { id } = useParams<{ id: string }>();
  const wsHref = useWsHref();
  const { data: a, error, reload } = useApi<Actor>(`/api/library/actors/${id}`);
  const [edit, setEdit] = useState(false);
  if (error) return <Page><ErrorState error={error} onRetry={reload} /></Page>;
  if (!a) return <Page><div className="space-y-3 pt-8"><Skeleton className="h-3 w-40" /><Skeleton className="h-8 w-1/3" /><Skeleton className="mt-6 h-40 w-full" /></div></Page>;
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Libraries" }, { label: "Threat actors", href: "/library/actors" }, { label: a.name }]} title={a.name}
        description={a.aliases.length ? `Also known as ${a.aliases.join(", ")}` : undefined}
        actions={<Button icon={<Pencil />} onClick={() => setEdit(true)}>Edit profile</Button>} />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-6">
          <Panel title="ATT&CK tactics">
            <TacticRail tactics={a.rail} />
          </Panel>
          {a.description && <Panel title="Profile"><p className="reading text-body-lg">{a.description}</p></Panel>}
          <Panel title="Techniques (TTP heatmap)">
            {a.techniques.length ? (
              <ul className="flex flex-wrap gap-2">
                {a.techniques.map((t) => (
                  <li key={t.id} className="flex max-w-full min-w-0 items-center gap-1"><AttackChip id={t.id} name={t.name.split(": ").pop()} /><Badge tone={t.count > 1 ? "accent" : "neutral"}>×{t.count}</Badge></li>
                ))}
              </ul>
            ) : <p className="text-fg-muted">No techniques mapped yet.</p>}
          </Panel>
          <SourceTrail items={a.provenance} total={a.provenance_total} wsHref={wsHref} />
          <SeenIn items={a.seen_in} />
        </div>
        <aside className="min-w-0 space-y-4">
          <Panel title="Details">
            <DefinitionList items={[
              { label: "Origin", value: a.origin || "—" },
              { label: "Motivation", value: a.motivation.join(", ") || "—" },
              { label: "Target industries", value: a.target_industries.join(", ") || "—" },
              { label: "Target regions", value: a.target_regions.join(", ") || "—" },
              { label: "First seen", value: utc(a.first_seen, false) },
              { label: "Last seen", value: utc(a.last_seen, false) },
              { label: "Research", value: a.research_count },
            ]} />
          </Panel>
          <Panel title="Known tools">
            {a.tools.length ? <div className="flex flex-wrap gap-1.5">{a.tools.map((t) => <Chip key={t.id} href={wsHref(`/library/malware/${t.id}`)} title={t.type}>{t.name}</Chip>)}</div> : <p className="text-fg-muted">None linked.</p>}
          </Panel>
          <p className="text-caption text-fg-muted"><Link href={wsHref(`/research?actor=${encodeURIComponent(a.name)}`)} className="prose-link">All research on {a.name}</Link></p>
        </aside>
      </div>
      <ActorEditor open={edit} onClose={() => setEdit(false)} a={a} onSaved={() => { setEdit(false); reload(); }} />
    </Page>
  );
}

function ActorEditor({ open, onClose, a, onSaved }: { open: boolean; onClose: () => void; a: Actor; onSaved: () => void }) {
  const toast = useToast();
  const [aliases, setAliases] = useState(a.aliases.join(", "));
  const [origin, setOrigin] = useState(a.origin);
  const [motivation, setMotivation] = useState(a.motivation.join(", "));
  const [regions, setRegions] = useState(a.target_regions.join(", "));
  const [description, setDescription] = useState(a.description);
  const [saving, setSaving] = useState(false);
  useEffect(() => { setAliases(a.aliases.join(", ")); setOrigin(a.origin); setMotivation(a.motivation.join(", ")); setRegions(a.target_regions.join(", ")); setDescription(a.description); }, [a, open]);
  const split = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);
  const save = async () => {
    setSaving(true);
    try {
      await patch(`/api/library/actors/${a.id}`, { aliases: split(aliases), origin, motivation: split(motivation), target_regions: split(regions), description });
      toast({ tone: "success", message: "Profile saved" });
      onSaved();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setSaving(false); }
  };
  return (
    <Dialog open={open} onClose={onClose} title={`Edit ${a.name}`} size="md" footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} onClick={save}>Save profile</Button></>}>
      <div className="space-y-5">
        <Field label="Aliases" htmlFor="a-al" help="Comma-separated. Research using any alias links to this profile."><Input id="a-al" value={aliases} onChange={(e) => setAliases(e.target.value)} /></Field>
        <Field label="Origin" htmlFor="a-or"><Input id="a-or" value={origin} onChange={(e) => setOrigin(e.target.value)} /></Field>
        <Field label="Motivation" htmlFor="a-mo" help="Comma-separated, e.g. espionage, financial"><Input id="a-mo" value={motivation} onChange={(e) => setMotivation(e.target.value)} /></Field>
        <Field label="Target regions" htmlFor="a-re"><Input id="a-re" value={regions} onChange={(e) => setRegions(e.target.value)} /></Field>
        <Field label="Profile" optional htmlFor="a-de"><Textarea id="a-de" value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      </div>
    </Dialog>
  );
}
