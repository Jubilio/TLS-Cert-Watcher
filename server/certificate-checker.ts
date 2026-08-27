import tls from "node:tls";
import { isIP } from "node:net";
import type { InsertCertificateCheck } from "@shared/schema";
import { resolveScanTarget, validatePort } from "./target-validation";

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1_000;
const DEFAULT_TIMEOUT_MS = 10_000;

export type CertificateStatus = "valid" | "warning" | "expired" | "error";

export function daysUntilExpiration(validUntil: Date, now = new Date()): number {
  const difference = (validUntil.getTime() - now.getTime()) / MILLISECONDS_PER_DAY;
  return difference >= 0 ? Math.ceil(difference) : Math.floor(difference);
}

export function classifyCertificate(
  validUntil: Date,
  now = new Date(),
  warningDays = 30,
): Exclude<CertificateStatus, "error"> {
  if (validUntil.getTime() < now.getTime()) return "expired";
  return daysUntilExpiration(validUntil, now) <= warningDays ? "warning" : "valid";
}

function errorResult(
  hostname: string,
  port: number,
  message: string,
): InsertCertificateCheck {
  return {
    hostname,
    port,
    status: "error",
    errorMessage: message,
    daysUntilExpiration: null,
    issuer: null,
    subject: null,
    validFrom: null,
    validUntil: null,
    batchId: null,
  };
}

export async function performCertificateCheck(
  rawHostname: string,
  rawPort: number,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<InsertCertificateCheck> {
  const port = validatePort(rawPort);
  const target = await resolveScanTarget(rawHostname);

  return new Promise((resolve) => {
    let completed = false;
    const finish = (result: InsertCertificateCheck) => {
      if (completed) return;
      completed = true;
      socket.destroy();
      resolve(result);
    };

    const socket = tls.connect({
      host: target.address,
      port,
      servername: isIP(target.hostname) ? undefined : target.hostname,
      rejectUnauthorized: false,
    });

    socket.setTimeout(timeoutMs);

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      if (!certificate || Object.keys(certificate).length === 0) {
        finish(errorResult(target.hostname, port, "Certificate not found or invalid"));
        return;
      }

      const validFrom = new Date(certificate.valid_from);
      const validUntil = new Date(certificate.valid_to);
      if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validUntil.getTime())) {
        finish(errorResult(target.hostname, port, "Certificate validity dates are invalid"));
        return;
      }

      finish({
        hostname: target.hostname,
        port,
        status: classifyCertificate(validUntil),
        daysUntilExpiration: daysUntilExpiration(validUntil),
        issuer: certificate.issuer?.CN || certificate.issuer?.O || "Unknown",
        subject: certificate.subject?.CN || certificate.subject?.O || "Unknown",
        validFrom,
        validUntil,
        errorMessage: null,
        batchId: null,
      });
    });

    socket.once("timeout", () => {
      finish(errorResult(target.hostname, port, "Connection timeout"));
    });

    socket.once("error", (error) => {
      finish(errorResult(target.hostname, port, error.message));
    });
  });
}
