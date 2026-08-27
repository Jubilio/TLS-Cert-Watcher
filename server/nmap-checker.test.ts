import assert from "node:assert/strict";
import test from "node:test";
import { parseNmapOutput } from "./nmap-checker";

test("parses Nmap NSE output including pipe prefixes", () => {
  const parsed = parseNmapOutput(`
| tls-expired-cert-checker:
|   Subject: example.com
|   Issuer: Example CA
|   Válido até: 2026-09-10T00:00:00Z
|_  ⚠️ ATENÇÃO: Certificado expira em 14 dias
`);

  assert.equal(parsed.status, "warning");
  assert.equal(parsed.daysUntilExpiration, 14);
  assert.equal(parsed.subject, "example.com");
  assert.equal(parsed.issuer, "Example CA");
  assert.equal(parsed.validUntil?.toISOString(), "2026-09-10T00:00:00.000Z");
});

test("returns negative days for an expired certificate", () => {
  const parsed = parseNmapOutput("|_ ❌ CRÍTICO: Certificado expirado há 5 dias!");
  assert.equal(parsed.status, "expired");
  assert.equal(parsed.daysUntilExpiration, -5);
});

test("returns an explicit error when output has no status", () => {
  const parsed = parseNmapOutput("Nmap done: 1 IP address scanned");
  assert.equal(parsed.status, "error");
  assert.equal(parsed.errorMessage, "Nmap returned no certificate status");
});
