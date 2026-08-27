import { execFile as execFileCallback } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import type { InsertCertificateCheck } from "@shared/schema";
import { resolveScanTarget, validatePort } from "./target-validation";

const execFile = promisify(execFileCallback);

export function getNseScriptPath(): string {
  return path.resolve(process.cwd(), "public", "tls-expired-cert-checker.nse");
}

export function parseNmapOutput(
  stdout: string,
): Pick<
  InsertCertificateCheck,
  "status" | "daysUntilExpiration" | "issuer" | "subject" | "validUntil" | "errorMessage"
> {
  let status = "unknown";
  let daysUntilExpiration: number | null = null;
  let issuer: string | null = null;
  let subject: string | null = null;
  let validUntil: Date | null = null;

  for (const raw of stdout.split("\n")) {
    const line = raw.trim().replace(/^\|_?\s*/, "");
    if (line.startsWith("✅")) status = "valid";
    if (line.includes("ATENÇÃO") || line.includes("URGENTE") || line.startsWith("⚠️")) {
      status = "warning";
    }
    if (line.includes("CRÍTICO") || line.startsWith("❌")) status = "expired";

    const days = line.match(/(\d+) dias?/);
    if (days) {
      const parsed = Number.parseInt(days[1], 10);
      daysUntilExpiration = line.includes("expirado há") ? -parsed : parsed;
    }

    if (line.startsWith("Issuer:")) issuer = line.replace(/^Issuer:\s*/i, "").trim();
    if (line.startsWith("Subject:")) subject = line.replace(/^Subject:\s*/i, "").trim();
    if (line.startsWith("Válido até:")) {
      const parsed = new Date(line.replace(/^Válido até:\s*/i, "").trim());
      if (!Number.isNaN(parsed.getTime())) validUntil = parsed;
    }
  }

  return {
    status: status === "unknown" ? "error" : status,
    daysUntilExpiration,
    issuer,
    subject,
    validUntil,
    errorMessage: status === "unknown" ? "Nmap returned no certificate status" : null,
  };
}

export async function performCertificateCheckNmap(
  rawHostname: string,
  rawPort: number,
): Promise<InsertCertificateCheck> {
  const port = validatePort(rawPort);
  const target = await resolveScanTarget(rawHostname);

  try {
    const { stdout } = await execFile(
      "nmap",
      ["-Pn", "-p", String(port), "--script", getNseScriptPath(), target.hostname, "-oN", "-"],
      { maxBuffer: 10 * 1024 * 1024, timeout: 30_000 },
    );

    return {
      hostname: target.hostname,
      port,
      validFrom: null,
      batchId: null,
      ...parseNmapOutput(stdout),
    };
  } catch (error) {
    const nodeError = error as NodeJS.ErrnoException & { killed?: boolean };
    const message =
      nodeError.code === "ENOENT"
        ? "Nmap is not installed on the server"
        : nodeError.killed
          ? "Nmap scan timed out"
          : "Nmap scan failed";

    return {
      hostname: target.hostname,
      port,
      status: "error",
      daysUntilExpiration: null,
      issuer: null,
      subject: null,
      validFrom: null,
      validUntil: null,
      errorMessage: message,
      batchId: null,
    };
  }
}
