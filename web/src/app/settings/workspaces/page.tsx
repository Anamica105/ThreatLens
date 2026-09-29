"use client";

import { Plus } from "lucide-react";
import Link from "next/link";
import { useApp } from "@/components/providers";
import { Chip } from "@/components/ui/badges";
import { ButtonLink } from "@/components/ui/button";
import { Page, PageHeader } from "@/components/ui/layout";

export default function WorkspacesList() {
  const { user, workspaces, platformName } = useApp();
  const canEdit = user?.role === "lead" || user?.role === "admin";
  return (
    <Page>
      <PageHeader crumbs={[{ label: "Settings", href: "/settings" }, { label: "Workspaces" }]} title="Workspaces"
        description="A workspace is a client profile: a filter plus defaults, not an isolation boundary."
        actions={canEdit && <ButtonLink href="/settings/workspaces/new" variant="primary" icon={<Plus />}>New workspace</ButtonLink>} />
      <div className="overflow-x-auto rounded-md border border-line bg-surface">
        <table className="tl-table tl-comfortable w-full">
          <thead><tr><th>Workspace</th><th>Industry</th><th>Output platforms</th><th>Technology in scope</th><th className="num">Research</th><th>Default TLP</th></tr></thead>
          <tbody>
            {workspaces.map((w) => (
              <tr key={w.id}>
                <td><Link href={`/settings/workspaces/${w.id}`} className="flex items-center gap-2 font-semibold hover:underline"><span className="size-2 rounded-full" style={{ background: w.color }} />{w.name}</Link></td>
                <td>{w.industry}</td>
                <td><span className="flex flex-wrap gap-1">{w.platforms.map((p) => <Chip key={p}>{platformName(p, true)}</Chip>)}</span></td>
                <td className="max-w-[320px] truncate text-fg-muted">{w.products.join(", ") || "—"}</td>
                <td className="num">{w.research_count ?? 0}</td>
                <td>TLP:{w.default_tlp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Page>
  );
}
