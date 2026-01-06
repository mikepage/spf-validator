/**
 * DNS Resolver Module for SPF Lookups
 *
 * Provides TXT record resolution with DNS-over-HTTPS backends:
 * - Google DNS-over-HTTPS
 * - Cloudflare DNS-over-HTTPS
 */

export type ResolverType = "google" | "cloudflare";

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

export interface ResolveOptions {
  resolver?: ResolverType;
}

/**
 * Resolve TXT records using DNS-over-HTTPS
 */
export async function resolveTxt(
  domain: string,
  options: ResolveOptions = {},
): Promise<string[]> {
  const { resolver = "google" } = options;

  const resolverFunctions: Record<ResolverType, (domain: string) => Promise<string[]>> = {
    google: resolveWithGoogleDoH,
    cloudflare: resolveWithCloudflareDoH,
  };

  return resolverFunctions[resolver](domain);
}
