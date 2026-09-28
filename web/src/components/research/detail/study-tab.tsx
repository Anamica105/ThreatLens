"use client";

import { Lightbulb, Pencil } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ResearchRecord } from "@/lib/types";
import { GeneratedBadge } from "../../ui/badges";
import { Button } from "../../ui/button";
import { Field, Textarea } from "../../ui/forms";
import { Dialog } from "../../ui/overlay";
import { ClaimConflict } from "../claim-conflict";
import { SectionHeading, SourceRefs, type DetailProps } from "./common";

/** Long-form digest a hunter reads instead of ten articles. */
export function StudyTab({ d, patchRecord, canEdit }: DetailProps) {
  const rec = d.record;
  const s = rec.study;
  const sources = useMemo(() => Object.fromEntries(rec.sources.map((x) => [x.id, x])), [rec.sources]);
  const [editing, setEditing] = useState(false);
  return (
    <div className="reading mx-auto space-y-10 xl:mx-0 xl:ml-[232px]">
      <div className="flex items-center gap-2">
        <GeneratedBadge state={rec.review?.study} />
        {canEdit && <Button size="sm" variant="tertiary" icon={<Pencil />} className="ml-auto" onClick={() => setEditing(true)}>Edit study notes</Button>}
      </div>
      <section>
        <SectionHeading id="study-background">Background</SectionHeading>
        <p className="text-body-lg">{s.background || "—"}</p>
      </section>
      {s.how_it_works && (
        <section>
          <SectionHeading id="study-how">How the exploit works</SectionHeading>
          <p className="text-body-lg">{s.how_it_works}</p>
        </section>
      )}
      {s.kill_chain_narrative && (
        <section>
          <SectionHeading id="study-chain">Kill chain</SectionHeading>
          <p className="text-body-lg">{s.kill_chain_narrative}</p>
          {rec.attack_paths.length > 0 && (
            <ol className="mt-4 space-y-3">
              {rec.attack_paths.map((p) => (
                <li key={p.id}>
                  <div className="text-h4 font-semibold">{p.name}</div>
                  <div className="mt-1 flex flex-wrap items-center gap-1 text-body-sm text-fg-strong">
                    {p.steps.map((st, i) => <span key={st.ref}>{i > 0 && <span className="px-1 text-fg-faint">→</span>}{st.behaviour.length > 60 ? st.behaviour.slice(0, 58) + "…" : st.behaviour}</span>)}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      )}
      {rec.timeline.length > 0 && (
        <section>
          <SectionHeading id="study-timeline">Timeline</SectionHeading>
          <ol className="space-y-2">
            {rec.timeline.map((t, i) => <li key={i} className="flex gap-4 text-body-lg"><span className="w-28 shrink-0 tabular text-fg-muted">{t.date}</span><span>{t.event}<SourceRefs ids={t.source_ids} sources={sources} /></span></li>)}
          </ol>
        </section>
      )}
      {rec.conflicts.length > 0 && (
        <section>
          <SectionHeading id="study-conflicts">Where sources disagree</SectionHeading>
          <div className="space-y-3">{rec.conflicts.map((c, i) => <ClaimConflict key={i} c={c} sources={sources} />)}</div>
        </section>
      )}
      {s.remember.length > 0 && (
        <section className="rounded-md border border-line bg-accent-soft p-5">
          <h2 className="mb-3 flex items-center gap-2 text-h2 font-semibold"><Lightbulb className="size-5 text-accent-text" />What you should remember</h2>
          <ul className="list-disc space-y-2 pl-5 text-body-lg">{s.remember.map((r, i) => <li key={i}>{r}</li>)}</ul>
        </section>
      )}
      <StudyEditor open={editing} onClose={() => setEditing(false)} study={s} onSave={async (v) => { await patchRecord({ study: v }, "Edited study notes"); setEditing(false); }} />
    </div>
  );
}

function StudyEditor({ open, onClose, study, onSave }: { open: boolean; onClose: () => void; study: ResearchRecord["study"]; onSave: (s: ResearchRecord["study"]) => Promise<void> }) {
  const [v, setV] = useState(study);
  const [remember, setRemember] = useState(study.remember.join("\n"));
  const [saving, setSaving] = useState(false);
  useEffect(() => { setV(study); setRemember(study.remember.join("\n")); }, [study, open]);
  return (
    <Dialog open={open} onClose={onClose} title="Edit study notes" size="lg"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} onClick={async () => { setSaving(true); try { await onSave({ ...v, remember: remember.split("\n").map((x) => x.trim()).filter(Boolean) }); } finally { setSaving(false); } }}>Save study notes</Button></>}>
      <div className="space-y-5">
        <Field label="Background" htmlFor="st-bg"><Textarea id="st-bg" value={v.background} onChange={(e) => setV({ ...v, background: e.target.value })} /></Field>
        <Field label="How it works" htmlFor="st-how"><Textarea id="st-how" value={v.how_it_works} onChange={(e) => setV({ ...v, how_it_works: e.target.value })} /></Field>
        <Field label="Kill chain narrative" htmlFor="st-kc"><Textarea id="st-kc" value={v.kill_chain_narrative} onChange={(e) => setV({ ...v, kill_chain_narrative: e.target.value })} /></Field>
        <Field label="What you should remember" htmlFor="st-rem" help="One point per line."><Textarea id="st-rem" value={remember} onChange={(e) => setRemember(e.target.value)} /></Field>
      </div>
    </Dialog>
  );
}
