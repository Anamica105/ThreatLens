"use client";

import { useApi } from "@/lib/hooks";
import type { User } from "@/lib/types";

/** A comment as returned by GET /api/research/{id}/comments (roots carry `replies`). */
export interface CommentItem {
  id: number;
  section: string | null;
  section_label: string;
  parent_id: number | null;
  message: string;
  user: User | null;
  created_at: string;
  mentions: User[];
  resolved: boolean;
  resolved_by: User | null;
  resolved_at: string | null;
}
export interface CommentThread extends CommentItem { replies: CommentItem[] }
export interface SectionCount { threads: number; open: number; comments: number }
export interface CommentsResponse { threads: CommentThread[]; counts: Record<string, SectionCount> }

export interface NotificationItem {
  id: number;
  kind: "mention" | "reply";
  research_id: string;
  research_title: string;
  section: string | null;
  section_label: string;
  comment_id: number;
  thread_id: number;
  message: string;
  by: User | null;
  created_at: string;
  read: boolean;
}
export interface NotificationsResponse { unread: number; items: NotificationItem[] }

/** Report section anchors (element ids in the Report tab) → record section keys used for comments. */
export const SECTION_BY_ANCHOR: Record<string, string> = {
  "executive-summary": "executive_summary", impact: "impact", recommendations: "recommendations", result: "result",
  vulnerabilities: "vulnerabilities", actors: "threat_actors", "attack-paths": "attack_paths", mitre: "mitre",
  opportunities: "detection_opportunities", ioas: "ioas", tools: "tools_used", workflow: "workflow", hunts: "hunts",
  iocs: "iocs", industries: "industries", timeline: "timeline",
};
export const ANCHOR_BY_SECTION: Record<string, string> = Object.fromEntries(Object.entries(SECTION_BY_ANCHOR).map(([a, s]) => [s, a]));

export const SECTION_LABEL: Record<string, string> = {
  executive_summary: "Executive summary", impact: "Impact", recommendations: "Recommendations", result: "Result",
  vulnerabilities: "Vulnerabilities", threat_actors: "Threat actors", attack_paths: "Attack paths", mitre: "MITRE ATT&CK",
  detection_opportunities: "Detection opportunities", ioas: "Indicators of attack", tools_used: "Tools used", workflow: "Workflow",
  hunts: "Hunts", iocs: "IoCs", industries: "Industries", timeline: "Timeline",
};
export const sectionLabel = (s: string | null | undefined) => (s ? SECTION_LABEL[s] ?? s.replace(/_/g, " ") : "General");

/** Link that opens a section's comment thread on the Report tab. */
export function threadHref(rid: string, section: string | null, commentId?: number, base = "") {
  const p = new URLSearchParams({ tab: "report", thread: section ?? "general" });
  if (commentId) p.set("c", String(commentId));
  return `${base || `/research/${rid}`}?${p.toString()}`;
}

export function useComments(rid: string) {
  return useApi<CommentsResponse>(`/api/research/${rid}/comments`);
}

/** Split a message into plain text and @mention runs for the given users (longest names first). */
export function mentionParts(message: string, users: User[]): { text: string; user?: User }[] {
  const names = [...users].sort((a, b) => b.name.length - a.name.length);
  const out: { text: string; user?: User }[] = [];
  let buf = "";
  for (let i = 0; i < message.length;) {
    if (message[i] === "@") {
      const rest = message.slice(i + 1);
      const u = names.find((x) => rest.toLowerCase().startsWith(x.name.toLowerCase()) && !/\w/.test(rest[x.name.length] ?? ""))
        ?? names.find((x) => rest.toLowerCase().startsWith(x.id.toLowerCase()) && !/\w/.test(rest[x.id.length] ?? ""));
      if (u) {
        if (buf) out.push({ text: buf });
        buf = "";
        const len = rest.toLowerCase().startsWith(u.name.toLowerCase()) ? u.name.length : u.id.length;
        out.push({ text: message.slice(i, i + 1 + len), user: u });
        i += 1 + len;
        continue;
      }
    }
    buf += message[i];
    i += 1;
  }
  if (buf) out.push({ text: buf });
  return out;
}
