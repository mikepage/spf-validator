/**
 * DNS Resolver Module for SPF Lookups
 *
 * Provides TXT record resolution with multiple backends:
 * - Native Deno DNS (fastest, but unavailable on Deno Deploy)
 * - Google DNS-over-HTTPS
 * - Cloudflare DNS-over-HTTPS
 */

export type ResolverType = "native" | "google" | "cloudflare";

interface GoogleDnsResponse {
  Status: number;
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
}

const DNS_STATUS_MESSAGES: Record<number, string> = {
  1: "Format error",
  2: "Server failure",
  3: "Non-existent domain",
  4: "Not implemented",
  5: "Query refused",
};

/**
 * Resolve TXT records using Google's DNS-over-HTTPS API
 */
export async function resolveWithGoogleDoH(domain: string): Promise<string[]> {
  const params = new URLSearchParams({
    name: domain,
    type: "16", // TXT record type
    cd: "true", // Disable DNSSEC validation
  });

  const url = `https://dns.google/resolve?${params}`;
  const response = await fetch(url, {
    headers: { Accept: "application/dns-json" },
  });

  if (!response.ok) {
    throw new Error(`Google DNS request failed: ${response.statusText}`);
  }

  const data: GoogleDnsResponse = await response.json();

  if (data.Status !== 0) {
    throw new Error(
      DNS_STATUS_MESSAGES[data.Status] || `DNS error: ${data.Status}`,
    );
  }

  if (!data.Answer) {
    return [];
  }

  return data.Answer
    .filter((a) => a.type === 16)
    .map((a) => a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
}

/**
 * Resolve TXT records using Cloudflare's DNS-over-HTTPS API
 */
export async function resolveWithCloudflareDoH(
  domain: string,
): Promise<string[]> {
  const params = new URLSearchParams({
    name: domain,
    type: "TXT",
    cd: "true",
  });

  const url = `https://cloudflare-dns.com/dns-query?${params}`;
  const response = await fetch(url, {
    headers: { Accept: "application/dns-json" },
  });

  if (!response.ok) {
    throw new Error(`Cloudflare DNS request failed: ${response.statusText}`);
  }

  const data: GoogleDnsResponse = await response.json();

  if (data.Status !== 0) {
    throw new Error(
      DNS_STATUS_MESSAGES[data.Status] || `DNS error: ${data.Status}`,
    );
  }

  if (!data.Answer) {
    return [];
  }

  return data.Answer
    .filter((a) => a.type === 16)
    .map((a) => a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
}

/**
 * Resolve TXT records using native Deno.resolveDns
 * Note: Not available on Deno Deploy
 */
export async function resolveWithNative(domain: string): Promise<string[]> {
  const records = await Deno.resolveDns(domain, "TXT");
  return records.map((record) =>
    Array.isArray(record) ? record.join("") : record
  );
}

const DNS_NATIVE_TIMEOUT_MS = 2000;

export interface ResolveOptions {
  resolver?: ResolverType;
  timeout?: number;
  fallbackResolvers?: ResolverType[];
}

const DEFAULT_FALLBACK_RESOLVERS: ResolverType[] = ["google", "cloudflare"];

/**
 * Resolve TXT records with automatic fallback
 *
 * By default, tries native DNS first, then falls back to DoH providers.
 */
export async function resolveTxt(
  domain: string,
  options: ResolveOptions = {},
): Promise<string[]> {
  const {
    resolver = "native",
    timeout = DNS_NATIVE_TIMEOUT_MS,
    fallbackResolvers = DEFAULT_FALLBACK_RESOLVERS,
  } = options;

  const resolverFunctions: Record<ResolverType, (domain: string) => Promise<string[]>> = {
    native: resolveWithNative,
    google: resolveWithGoogleDoH,
    cloudflare: resolveWithCloudflareDoH,
  };

  // If not using native, go directly to the specified resolver
  if (resolver !== "native") {
    return resolverFunctions[resolver](domain);
  }

  // Try native with timeout, then fallback to DoH
  try {
    const result = await Promise.race([
      resolveWithNative(domain),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("DNS timeout")), timeout)
      ),
    ]);
    return result;
  } catch {
    // Try fallback resolvers in order
    let lastError: Error | null = null;

    for (const fallbackResolver of fallbackResolvers) {
      try {
        return await resolverFunctions[fallbackResolver](domain);
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    throw lastError || new Error("All DNS resolvers failed");
  }
}
