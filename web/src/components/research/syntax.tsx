/** Lightweight syntax colouring for SPL, KQL, CQL, S1QL, XQL, ES|QL, YARA-L, AQL and Sigma. */

const KEYWORDS: Record<string, string[]> = {
  spl: ["stats", "table", "fields", "search", "where", "eval", "convert", "by", "as", "OR", "AND", "NOT", "index", "sourcetype", "tstats", "rename", "sort", "dedup", "values", "count", "min", "max", "ctime", "in", "IN"],
  kql: ["where", "project", "summarize", "extend", "union", "join", "let", "by", "and", "or", "not", "in", "in~", "has", "has_any", "has_all", "contains", "startswith", "endswith", "ago", "make_set", "dcount", "count", "take", "top", "order", "sort", "distinct", "on", "kind"],
  cql: ["table", "groupBy", "in", "select", "sort", "head", "count", "field", "values", "or", "and", "not"],
  s1ql: ["and", "or", "not", "in", "contains", "anycase", "endswith", "startswith", "in:anycase", "contains:anycase", "endswith:anycase", "startswith:anycase"],
  xql: ["config", "timeframe", "dataset", "filter", "fields", "comp", "sort", "limit", "and", "or", "not", "contains", "lowercase", "alter", "dedup", "preset", "in"],
  esql: ["FROM", "WHERE", "KEEP", "STATS", "BY", "LIKE", "AND", "OR", "NOT", "NOW", "IS", "NULL", "EVAL", "SORT", "LIMIT", "COUNT", "days"],
  yaral: ["rule", "meta", "events", "condition", "match", "outcome", "over", "nocase", "and", "or", "not", "re.regex"],
  aql: ["SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "ILIKE", "LIKE", "LAST", "DAYS", "GROUP", "BY", "ORDER", "AS", "events", "flows", "DATEFORMAT", "LOGSOURCETYPENAME"],
  sigma: ["title", "id", "status", "description", "tags", "logsource", "category", "product", "service", "detection", "selection", "condition", "falsepositives", "level", "references", "author"],
};

function family(platform: string) {
  if (platform.startsWith("kql")) return "kql";
  return platform in KEYWORDS ? platform : "kql";
}

const TOKEN = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`|\/\/.*$|#(?!event_simpleName|repo|type)[^\n]*$|\/(?:\\.|[^/\n])+\/[a-z]*|\b\d+(?:\.\d+)?[dhms]?\b|[|=!<>~]+|[A-Za-z_#@$][\w.:\-#@$~]*)/gm;

export function highlight(body: string, platform: string): React.ReactNode[] {
  const fam = family(platform);
  const kw = new Set(KEYWORDS[fam]);
  const out: React.ReactNode[] = [];
  let last = 0;
  let i = 0;
  for (const m of body.matchAll(TOKEN)) {
    const tok = m[0];
    const start = m.index ?? 0;
    if (start > last) out.push(body.slice(last, start));
    let cls = "";
    if (/^["'`]/.test(tok)) cls = "syn-s";
    else if (tok.startsWith("//") || (tok.startsWith("#") && fam !== "cql")) cls = "syn-c";
    else if (/^\/.+\/[a-z]*$/.test(tok)) cls = "syn-s";
    else if (/^\d/.test(tok)) cls = "syn-n";
    else if (/^[|=!<>~]+$/.test(tok)) cls = "syn-o";
    else if (kw.has(tok) || kw.has(tok.toLowerCase()) && fam !== "esql" && fam !== "aql") cls = "syn-k";
    else if (/^[A-Za-z_][\w.]*$/.test(tok) && body[start + tok.length] === "(") cls = "syn-f";
    else if (fam === "sigma" && body[start + tok.length] === ":") cls = "syn-k";
    else if (/^(#event_simpleName|#repo|#type)$/.test(tok) || /^[A-Z][A-Za-z0-9]+(?:\.[A-Za-z0-9_]+)*$/.test(tok) || /^[a-z]+(?:[._][a-z0-9_]+)+$/.test(tok) || /^\$e\./.test(tok)) cls = "syn-d";
    out.push(cls ? <span key={i++} className={cls}>{tok}</span> : tok);
    last = start + tok.length;
  }
  if (last < body.length) out.push(body.slice(last));
  return out;
}
