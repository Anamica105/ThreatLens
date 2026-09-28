"use client";

import { Building2, ChevronRight, KeyRound, ServerCog } from "lucide-react";
import Link from "next/link";
import { Page, PageHeader } from "@/components/ui/layout";

const ITEMS = [
  { href: "/settings/workspaces", icon: Building2, title: "Workspaces", body: "Client profiles: query platforms, log sources, technology in scope, field mappings and report branding." },
  { href: "/settings/osint", icon: KeyRound, title: "OSINT API keys", body: "VirusTotal, AbuseIPDB, GreyNoise, abuse.ch, Shodan, OTX and urlscan.io keys used for IoC enrichment." },
  { href: "/settings/system", icon: ServerCog, title: "System", body: "LLM and search configuration status, and the MITRE ATT&CK catalog sync." },
];

export default function SettingsIndex() {
  return (
    <Page>
      <PageHeader title="Settings" />
      <div className="grid max-w-3xl gap-3">
        {ITEMS.map(({ href, icon: Icon, title, body }) => (
          <Link key={href} href={href} className="flex items-center gap-4 rounded-md border border-line bg-surface p-4 hover:border-line-hover">
            <span className="grid size-10 place-items-center rounded-md bg-accent-soft text-accent-text"><Icon className="size-5" /></span>
            <span className="flex-1"><span className="block text-h4 font-semibold">{title}</span><span className="block text-body-sm text-fg-muted">{body}</span></span>
            <ChevronRight className="size-5 text-fg-muted" />
          </Link>
        ))}
      </div>
    </Page>
  );
}
