import dns from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export class TargetValidationError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
    super(message);
    this.name = "TargetValidationError";
  }
}

export function normalizeHostname(input: string): string {
  const trimmed = input.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!trimmed || trimmed.length > 253) {
    throw new TargetValidationError("Hostname must contain between 1 and 253 characters");
  }

  if (isIP(trimmed)) {
    return trimmed.toLowerCase();
  }

  const hostname = domainToASCII(trimmed).toLowerCase();
  const labels = hostname.split(".");
  const valid =
    hostname.length > 0 &&
    hostname.length <= 253 &&
    labels.every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    );

  if (!valid) {
    throw new TargetValidationError("Invalid hostname or IP address");
  }

  return hostname;
}

export function validatePort(input: number): number {
  if (!Number.isInteger(input) || input < 1 || input > 65_535) {
    throw new TargetValidationError("Port must be an integer between 1 and 65535");
  }

  return input;
}

function isBlockedIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) {
    return true;
  }

  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51) ||
    (a === 203 && b === 0) ||
    a >= 224
  );
}

function mappedIpv4(address: string): string | null {
  if (!address.startsWith("::ffff:")) return null;

  const tail = address.slice(7);
  if (isIP(tail) === 4) return tail;

  const groups = tail.split(":");
  if (groups.length !== 2) return null;
  const high = Number.parseInt(groups[0], 16);
  const low = Number.parseInt(groups[1], 16);
  if (!Number.isFinite(high) || !Number.isFinite(low)) return null;

  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

export function isBlockedAddress(address: string): boolean {
  const normalized = address.toLowerCase().split("%")[0];
  const family = isIP(normalized);

  if (family === 4) return isBlockedIpv4(normalized);
  if (family !== 6) return true;

  const mapped = mappedIpv4(normalized);
  if (mapped) return isBlockedIpv4(mapped);

  if (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("2001:db8:")
  ) {
    return true;
  }

  const firstGroup = normalized.split(":")[0];
  const first = Number.parseInt(firstGroup || "0", 16);
  return (
    (first & 0xfe00) === 0xfc00 ||
    (first & 0xffc0) === 0xfe80 ||
    (first & 0xff00) === 0xff00
  );
}

export interface ResolvedTarget {
  hostname: string;
  address: string;
  family: 4 | 6;
}

export async function resolveScanTarget(
  rawHostname: string,
  options: { allowPrivate?: boolean } = {},
): Promise<ResolvedTarget> {
  const hostname = normalizeHostname(rawHostname);
  const allowPrivate = options.allowPrivate ?? process.env.ALLOW_PRIVATE_TARGETS === "true";

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new TargetValidationError("Hostname could not be resolved");
  }

  if (addresses.length === 0) {
    throw new TargetValidationError("Hostname did not resolve to an IP address");
  }

  if (!allowPrivate && addresses.some(({ address }) => isBlockedAddress(address))) {
    throw new TargetValidationError(
      "Private, loopback, link-local, and reserved targets are blocked",
    );
  }

  const selected = addresses[0];
  return {
    hostname,
    address: selected.address,
    family: selected.family as 4 | 6,
  };
}
