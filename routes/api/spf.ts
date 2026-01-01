import { define } from "../../utils.ts";

interface SpfMechanism {
  type: string;
  qualifier: string;
  value: string;
  expanded?: SpfResult;
}

interface SpfValidationIssue {
  type: "error" | "warning";
  message: string;
}

interface SpfResult {
  domain: string;
  record: string | null;
  version: string | null;
  mechanisms: SpfMechanism[];
  lookupCount: number;
  issues: SpfValidationIssue[];
  queryTime: number;
}

interface LookupContext {
  count: number;
  maxLookups: number;
  visited: Set<string>;
}

const LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists", "redirect"];
const MAX_DNS_LOOKUPS = 10;

interface FetchSpfResult {
  record: string | null;
  error?: string;
  totalTxtRecords?: number;
}

interface GoogleDnsResponse {
  Status: number;
  Answer?: Array<{
    type: number;
    data: string;
  }>;
}

async function fetchSpfRecordViaDoh(domain: string): Promise<FetchSpfResult> {
  const url = `https://dns.google/resolve?name=${
    encodeURIComponent(domain)
  }&type=TXT`;
  const response = await fetch(url, {
    headers: { Accept: "application/dns-json" },
  });

  if (!response.ok) {
    throw new Error(`DoH request failed: ${response.status}`);
  }

  const data: GoogleDnsResponse = await response.json();

  if (data.Status !== 0) {
    throw new Error(`DNS query failed with status ${data.Status}`);
  }

  const txtRecords = data.Answer?.filter((a) => a.type === 16) ?? [];

  for (const record of txtRecords) {
    const txt = record.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "");
    if (txt.toLowerCase().startsWith("v=spf1")) {
      return { record: txt, totalTxtRecords: txtRecords.length };
    }
  }

  return {
    record: null,
    totalTxtRecords: txtRecords.length,
    error: txtRecords.length > 0
      ? `No SPF record found among ${txtRecords.length} TXT records`
      : "No TXT records found",
  };
}

async function fetchSpfRecordNative(domain: string): Promise<FetchSpfResult> {
  const records = await Deno.resolveDns(domain, "TXT");
  for (const record of records) {
    const txt = Array.isArray(record) ? record.join("") : record;
    if (txt.toLowerCase().startsWith("v=spf1")) {
      return { record: txt, totalTxtRecords: records.length };
    }
  }
  return {
    record: null,
    totalTxtRecords: records.length,
    error: records.length > 0
      ? `No SPF record found among ${records.length} TXT records`
      : "No TXT records found",
  };
}

const DNS_NATIVE_TIMEOUT_MS = 2000;

async function fetchSpfRecord(domain: string): Promise<FetchSpfResult> {
  try {
    const result = await Promise.race([
      fetchSpfRecordNative(domain),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("DNS timeout")), DNS_NATIVE_TIMEOUT_MS)
      ),
    ]);
    return result;
  } catch {
    // Fallback to DNS-over-HTTPS (for Deno Deploy or restricted environments)
    try {
      return await fetchSpfRecordViaDoh(domain);
    } catch (err) {
      return {
        record: null,
        error: `DNS lookup failed: ${
          err instanceof Error ? err.message : "Unknown error"
        }`,
      };
    }
  }
}

function parseSpfRecord(record: string): {
  version: string | null;
  mechanisms: SpfMechanism[];
  issues: SpfValidationIssue[];
} {
  const issues: SpfValidationIssue[] = [];
  const mechanisms: SpfMechanism[] = [];

  const parts = record.trim().split(/\s+/);
  if (parts.length === 0) {
    issues.push({ type: "error", message: "Empty SPF record" });
    return { version: null, mechanisms, issues };
  }

  const versionPart = parts[0].toLowerCase();
  if (!versionPart.startsWith("v=spf1")) {
    issues.push({
      type: "error",
      message: `Invalid version: expected "v=spf1", got "${parts[0]}"`,
    });
    return { version: null, mechanisms, issues };
  }

  const version = "spf1";

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) continue;

    let qualifier = "+";
    let term = part;

    if (/^[+\-~?]/.test(part)) {
      qualifier = part[0];
      term = part.slice(1);
    }

    const colonIndex = term.indexOf(":");
    const slashIndex = term.indexOf("/");
    let type: string;
    let value: string;

    if (colonIndex > 0) {
      type = term.slice(0, colonIndex).toLowerCase();
      value = term.slice(colonIndex + 1);
    } else if (slashIndex > 0) {
      type = term.slice(0, slashIndex).toLowerCase();
      value = term.slice(slashIndex);
    } else if (term.includes("=")) {
      const eqIndex = term.indexOf("=");
      type = term.slice(0, eqIndex).toLowerCase();
      value = term.slice(eqIndex + 1);
    } else {
      type = term.toLowerCase();
      value = "";
    }

    mechanisms.push({ type, qualifier, value });

    if (type === "ptr") {
      issues.push({
        type: "warning",
        message: `"ptr" mechanism is deprecated (RFC 7208 Section 5.5)`,
      });
    }
  }

  const allIndex = mechanisms.findIndex((m) => m.type === "all");
  if (allIndex >= 0 && allIndex !== mechanisms.length - 1) {
    issues.push({
      type: "warning",
      message: `"all" mechanism should be the last term in the record`,
    });
  }

  if (allIndex < 0) {
    issues.push({
      type: "warning",
      message:
        `No "all" mechanism found. Consider adding "-all" or "~all" at the end`,
    });
  }

  const redirectCount = mechanisms.filter((m) => m.type === "redirect").length;
  if (redirectCount > 1) {
    issues.push({
      type: "error",
      message: `Multiple "redirect" modifiers found (only one allowed)`,
    });
  }

  if (redirectCount > 0 && allIndex >= 0) {
    issues.push({
      type: "warning",
      message:
        `Both "redirect" and "all" present. "redirect" is ignored when "all" is present`,
    });
  }

  if (record.length > 255) {
    const chunks = Math.ceil(record.length / 255);
    issues.push({
      type: "warning",
      message:
        `Record exceeds 255 characters (${record.length} chars). Will be split into ${chunks} TXT strings`,
    });
  }

  return { version, mechanisms, issues };
}

async function expandMechanism(
  mechanism: SpfMechanism,
  ctx: LookupContext,
): Promise<SpfMechanism> {
  if (!LOOKUP_MECHANISMS.includes(mechanism.type)) {
    return mechanism;
  }

  if (mechanism.type !== "include" && mechanism.type !== "redirect") {
    ctx.count++;
    return mechanism;
  }

  const targetDomain = mechanism.value;
  if (!targetDomain) {
    return {
      ...mechanism,
      expanded: {
        domain: "",
        record: null,
        version: null,
        mechanisms: [],
        lookupCount: 0,
        issues: [{
          type: "error",
          message: "Missing domain for include/redirect",
        }],
        queryTime: 0,
      },
    };
  }

  if (ctx.visited.has(targetDomain.toLowerCase())) {
    return {
      ...mechanism,
      expanded: {
        domain: targetDomain,
        record: null,
        version: null,
        mechanisms: [],
        lookupCount: 0,
        issues: [
          {
            type: "error",
            message: `Circular reference detected: ${targetDomain}`,
          },
        ],
        queryTime: 0,
      },
    };
  }

  ctx.count++;

  if (ctx.count > ctx.maxLookups) {
    return {
      ...mechanism,
      expanded: {
        domain: targetDomain,
        record: null,
        version: null,
        mechanisms: [],
        lookupCount: 0,
        issues: [
          {
            type: "error",
            message: `DNS lookup limit exceeded (${ctx.maxLookups})`,
          },
        ],
        queryTime: 0,
      },
    };
  }

  ctx.visited.add(targetDomain.toLowerCase());

  const expandedResult = await lookupSpf(targetDomain, ctx);

  return {
    ...mechanism,
    expanded: expandedResult,
  };
}

async function lookupSpf(
  domain: string,
  ctx: LookupContext,
): Promise<SpfResult> {
  const startTime = performance.now();
  const issues: SpfValidationIssue[] = [];

  const spfResult = await fetchSpfRecord(domain);

  if (!spfResult.record) {
    return {
      domain,
      record: null,
      version: null,
      mechanisms: [],
      lookupCount: ctx.count,
      issues: [{
        type: "error",
        message: spfResult.error || `No SPF record found for ${domain}`,
      }],
      queryTime: Math.round(performance.now() - startTime),
    };
  }

  const record = spfResult.record;

  const parsed = parseSpfRecord(record);
  issues.push(...parsed.issues);

  const expandedMechanisms: SpfMechanism[] = [];
  for (const mechanism of parsed.mechanisms) {
    const expanded = await expandMechanism(mechanism, ctx);
    expandedMechanisms.push(expanded);
  }

  return {
    domain,
    record,
    version: parsed.version,
    mechanisms: expandedMechanisms,
    lookupCount: ctx.count,
    issues,
    queryTime: Math.round(performance.now() - startTime),
  };
}

export const handler = define.handlers({
  async GET(ctx) {
    const url = new URL(ctx.req.url);
    const domain = url.searchParams.get("domain");

    if (!domain) {
      return Response.json(
        { success: false, error: "Domain is required" },
        { status: 400 },
      );
    }

    const cleanDomain = domain.trim().toLowerCase();
    if (
      !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(cleanDomain) &&
      cleanDomain.length > 1
    ) {
      return Response.json(
        { success: false, error: "Invalid domain format" },
        { status: 400 },
      );
    }

    try {
      const lookupContext: LookupContext = {
        count: 0,
        maxLookups: MAX_DNS_LOOKUPS,
        visited: new Set([cleanDomain]),
      };

      const result = await lookupSpf(cleanDomain, lookupContext);

      if (result.lookupCount > MAX_DNS_LOOKUPS) {
        result.issues.push({
          type: "error",
          message:
            `Too many DNS lookups: ${result.lookupCount} (RFC 7208 allows max ${MAX_DNS_LOOKUPS})`,
        });
      }

      return Response.json({
        success: true,
        result,
      });
    } catch (err) {
      const errorMessage = err instanceof Error
        ? err.message
        : "SPF lookup failed";
      return Response.json(
        { success: false, error: errorMessage },
        { status: 500 },
      );
    }
  },
});
