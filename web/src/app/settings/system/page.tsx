"use client";

import { RefreshCw } from "lucide-react";
import { useState } from "react";
import { Pill } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { SkeletonRows, useToast } from "@/components/ui/feedback";
import { DefinitionList, Page, PageHeader, Panel } from "@/components/ui/layout";
import { post } from "@/lib/api";
import { useApi } from "@/lib/hooks";

interface Sys { llm: { available: boolean; model: string }; search: { available: boolean }; database: string; attack: { version: string; techniques: number } }

export default function SystemSettings() {
  const toast = useToast();
  const { data, reload } = useApi<Sys>("/api/settings/system");
  const [syncing, setSyncing] = useState(false);
  const sync = async () => {
    setSyncing(true);
    try {
      const r = await post<{ version: string; techniques: number }>("/api/settings/attack-sync");
      toast({ tone: "success", message: `ATT&CK synced: v${r.version}, ${r.techniques} techniques` });
      reload();
    } catch (e) { toast({ tone: "danger", message: (e as Error).message }); } finally { setSyncing(false); }
  };
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Settings", href: "/settings" }, { label: "System" }]} title="System" description="Configured on the API server through environment variables (api/.env)." />
      {!data ? <SkeletonRows /> : (
        <div className="grid max-w-4xl gap-6 md:grid-cols-2">
          <Panel title="LLM agents">
            <DefinitionList items={[
              { label: "Status", value: data.llm.available ? <Pill tone="success">Connected</Pill> : <Pill tone="warning">Offline mode</Pill> },
              { label: "Model", value: <span className="font-mono">{data.llm.model}</span> },
              { label: "Configure", value: <span className="text-body-sm">Set <code className="font-mono">ANTHROPIC_API_KEY</code> and restart the API.</span> },
            ]} />
          </Panel>
          <Panel title="Source discovery">
            <DefinitionList items={[
              { label: "Vendor feeds", value: <Pill tone="success">Enabled</Pill> },
              { label: "Open-web search", value: data.search.available ? <Pill tone="success">Brave Search</Pill> : <Pill tone="neutral">Not configured</Pill> },
              { label: "Configure", value: <span className="text-body-sm">Set <code className="font-mono">BRAVE_SEARCH_API_KEY</code>.</span> },
            ]} />
          </Panel>
          <Panel title="MITRE ATT&CK" actions={<Button size="sm" icon={<RefreshCw />} loading={syncing} onClick={sync}>Sync now</Button>}>
            <DefinitionList items={[
              { label: "Catalog", value: data.attack.version === "bundled subset" ? "Bundled subset" : `Enterprise v${data.attack.version}` },
              { label: "Techniques", value: data.attack.techniques },
              { label: "Note", value: <span className="text-body-sm">Sync downloads the current Enterprise STIX bundle from MITRE. Every mapped technique ID is validated against it.</span> },
            ]} />
          </Panel>
          <Panel title="Storage">
            <DefinitionList items={[{ label: "Database", value: data.database }, { label: "Articles", value: "api/data/articles" }]} />
          </Panel>
        </div>
      )}
    </Page>
  );
}
