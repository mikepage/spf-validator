import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";

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

function parseHash(hash: string): string | null {
  const match = hash.match(/^#(.+?)\/?\s*$/);
  if (!match) return null;
  return match[1];
}

function updateHash(domain: string) {
  if (domain) {
    globalThis.history.replaceState(null, "", `#${domain}`);
  } else {
    globalThis.history.replaceState(null, "", globalThis.location.pathname);
  }
}

function getQualifierColor(qualifier: string): string {
  switch (qualifier) {
    case "+":
      return "text-green-600";
    case "-":
      return "text-red-600";
    case "~":
      return "text-yellow-600";
    case "?":
      return "text-gray-500";
    default:
      return "text-gray-700";
  }
}

function getQualifierLabel(qualifier: string): string {
  switch (qualifier) {
    case "+":
      return "Pass";
    case "-":
      return "Fail";
    case "~":
      return "SoftFail";
    case "?":
      return "Neutral";
    default:
      return "";
  }
}

function MechanismDisplay({
  mechanism,
  depth = 0,
}: {
  mechanism: SpfMechanism;
  depth?: number;
}) {
  const isExpanded = mechanism.type === "include" && mechanism.expanded;
  const indent = depth * 16;

  return (
    <div>
      <div
        class="flex items-start gap-2 py-1 font-mono text-sm"
        style={{ marginLeft: `${indent}px` }}
      >
        <span class={`font-bold ${getQualifierColor(mechanism.qualifier)}`}>
          {mechanism.qualifier}
        </span>
        <span class="text-blue-600">{mechanism.type}</span>
        {mechanism.value && (
          <>
            <span class="text-gray-400">:</span>
            <span class="text-gray-800">{mechanism.value}</span>
          </>
        )}
        <span class="text-gray-400 text-xs ml-2">
          ({getQualifierLabel(mechanism.qualifier)})
        </span>
      </div>
      {isExpanded && mechanism.expanded && (
        <div class="border-l-2 border-gray-200 ml-2">
          {mechanism.expanded.issues.length > 0 && (
            <div style={{ marginLeft: `${indent + 16}px` }} class="py-1">
              {mechanism.expanded.issues.map((issue, i) => (
                <div
                  key={i}
                  class={`text-xs ${
                    issue.type === "error" ? "text-red-600" : "text-yellow-600"
                  }`}
                >
                  {issue.type === "error" ? "Error" : "Warning"}:{" "}
                  {issue.message}
                </div>
              ))}
            </div>
          )}
          {mechanism.expanded.mechanisms.map((m, i) => (
            <MechanismDisplay key={i} mechanism={m} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function SpfValidator() {
  const domain = useSignal("");
  const isLoading = useSignal(false);
  const result = useSignal<SpfResult | null>(null);
  const error = useSignal<string | null>(null);
  const initialLoadDone = useSignal(false);

  const handleLookup = async () => {
    error.value = null;
    result.value = null;

    const domainValue = domain.value.trim();
    if (!domainValue) {
      error.value = "Please enter a domain name";
      return;
    }

    isLoading.value = true;

    try {
      const response = await fetch(
        `/api/spf?domain=${encodeURIComponent(domainValue)}`,
      );
      const data = await response.json();

      if (!data.success) {
        error.value = data.error || "SPF lookup failed";
        return;
      }

      result.value = data.result;
    } catch {
      error.value = "Failed to perform SPF lookup";
    } finally {
      isLoading.value = false;
    }
  };

  const handleClear = () => {
    domain.value = "";
    result.value = null;
    error.value = null;
    updateHash("");
  };

  useEffect(() => {
    const handleHashChange = () => {
      const parsed = parseHash(globalThis.location.hash);
      if (parsed) {
        domain.value = parsed;
        if (!initialLoadDone.value) {
          initialLoadDone.value = true;
          handleLookup();
        }
      } else {
        initialLoadDone.value = true;
      }
    };

    handleHashChange();

    globalThis.addEventListener("hashchange", handleHashChange);
    return () => globalThis.removeEventListener("hashchange", handleHashChange);
  }, []);

  useEffect(() => {
    if (initialLoadDone.value) {
      updateHash(domain.value.trim());
    }
  }, [domain.value]);

  const getLookupCountColor = (count: number): string => {
    if (count > 10) return "text-red-600 bg-red-50";
    if (count > 7) return "text-yellow-600 bg-yellow-50";
    return "text-green-600 bg-green-50";
  };

  return (
    <div class="w-full">
      {/* Input Section */}
      <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-4">
          SPF Record Lookup
        </h2>

        <div class="mb-4">
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Domain Name
          </label>
          <input
            type="text"
            value={domain.value}
            onInput={(
              e,
            ) => (domain.value = (e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleLookup();
            }}
            placeholder="example.com"
            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
          />
        </div>

        <div class="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={handleLookup}
            disabled={!domain.value.trim() || isLoading.value}
            class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
          >
            {isLoading.value ? "Validating..." : "Validate SPF"}
          </button>
          <button
            type="button"
            onClick={handleClear}
            class="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Error */}
      {error.value && (
        <div class="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <p class="text-red-600">{error.value}</p>
        </div>
      )}

      {/* Results */}
      {result.value && (
        <div class="space-y-6">
          {/* Summary Card */}
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">
              SPF Record for {result.value.domain}
            </h3>

            <div class="space-y-4">
              {/* Raw Record */}
              <div>
                <span class="text-sm text-gray-500">TXT Record</span>
                <pre class="font-mono text-sm bg-gray-50 p-3 rounded mt-1 break-all whitespace-pre-wrap">
                  {result.value.record || "No SPF record found"}
                </pre>
              </div>

              {/* Stats Grid */}
              <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <span class="text-sm text-gray-500">Version</span>
                  <p class="font-mono text-sm bg-gray-50 p-2 rounded mt-1">
                    {result.value.version || "N/A"}
                  </p>
                </div>
                <div>
                  <span class="text-sm text-gray-500">DNS Lookups</span>
                  <p
                    class={`font-mono text-sm p-2 rounded mt-1 ${
                      getLookupCountColor(
                        result.value.lookupCount,
                      )
                    }`}
                  >
                    {result.value.lookupCount} / 10
                    {result.value.lookupCount > 10 && " (Exceeded!)"}
                  </p>
                </div>
                <div>
                  <span class="text-sm text-gray-500">Query Time</span>
                  <p class="font-mono text-sm bg-gray-50 p-2 rounded mt-1">
                    {result.value.queryTime}ms
                  </p>
                </div>
              </div>

              {/* Validation Issues */}
              {result.value.issues.length > 0 && (
                <div>
                  <span class="text-sm text-gray-500">Validation Issues</span>
                  <div class="mt-1 space-y-2">
                    {result.value.issues.map((issue, i) => (
                      <div
                        key={i}
                        class={`text-sm p-2 rounded ${
                          issue.type === "error"
                            ? "bg-red-50 text-red-700 border border-red-200"
                            : "bg-yellow-50 text-yellow-700 border border-yellow-200"
                        }`}
                      >
                        <span class="font-medium">
                          {issue.type === "error" ? "Error" : "Warning"}:
                        </span>{" "}
                        {issue.message}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Mechanisms Breakdown */}
          {result.value.mechanisms.length > 0 && (
            <div class="bg-white rounded-lg shadow p-6">
              <h3 class="text-lg font-semibold text-gray-800 mb-4">
                Mechanisms Breakdown
              </h3>
              <div class="bg-gray-50 rounded p-4">
                {result.value.mechanisms.map((mechanism, i) => (
                  <MechanismDisplay key={i} mechanism={mechanism} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Reference Section */}
      <details class="bg-white rounded-lg shadow mt-6">
        <summary class="p-4 cursor-pointer font-medium text-gray-800 hover:bg-gray-50">
          SPF Mechanism Reference (RFC 7208)
        </summary>
        <div class="p-4 pt-0 border-t">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-gray-500">
                <th class="pb-2">Mechanism</th>
                <th class="pb-2">Description</th>
              </tr>
            </thead>
            <tbody class="text-gray-700">
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">all</td>
                <td class="py-2">
                  Matches all addresses (usually at end with - or ~)
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">include</td>
                <td class="py-2">
                  Include SPF record from another domain (counts as lookup)
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">a</td>
                <td class="py-2">
                  Match if IP matches A/AAAA record (counts as lookup)
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">mx</td>
                <td class="py-2">
                  Match if IP matches MX record (counts as lookup)
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">ip4</td>
                <td class="py-2">Match IPv4 address or CIDR range</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">ip6</td>
                <td class="py-2">Match IPv6 address or CIDR range</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">ptr</td>
                <td class="py-2">
                  Reverse DNS lookup (deprecated, counts as lookup)
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">exists</td>
                <td class="py-2">
                  Check if domain has A record (counts as lookup)
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">redirect</td>
                <td class="py-2">
                  Use SPF record from another domain instead
                </td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">exp</td>
                <td class="py-2">Explanation string for failures</td>
              </tr>
            </tbody>
          </table>

          <h4 class="font-medium text-gray-800 mt-6 mb-2">Qualifiers</h4>
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-gray-500">
                <th class="pb-2">Symbol</th>
                <th class="pb-2">Result</th>
                <th class="pb-2">Meaning</th>
              </tr>
            </thead>
            <tbody class="text-gray-700">
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono text-green-600">+</td>
                <td class="py-2">Pass</td>
                <td class="py-2">IP is authorized (default if omitted)</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono text-red-600">-</td>
                <td class="py-2">Fail</td>
                <td class="py-2">IP is not authorized, reject</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono text-yellow-600">~</td>
                <td class="py-2">SoftFail</td>
                <td class="py-2">IP is not authorized, but accept</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono text-gray-500">?</td>
                <td class="py-2">Neutral</td>
                <td class="py-2">No policy statement</td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
