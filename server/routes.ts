import type { Express, Response } from "express";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import packageMetadata from "../package.json" with { type: "json" };
import type { CertificateCheck, InsertCertificateCheck } from "@shared/schema";
import {
  batchScanRequestSchema,
  scanTargetSchema,
  scheduleScanRequestSchema,
  updateScheduledScanSchema,
} from "@shared/schema";
import { performCertificateCheck } from "./certificate-checker";
import { getNseScriptPath, performCertificateCheckNmap } from "./nmap-checker";
import { createRateLimiter } from "./rate-limit";
import { storage } from "./storage";
import { TargetValidationError } from "./target-validation";

const scanRequestSchema = scanTargetSchema;
const checkQuerySchema = z.object({
  port: z.coerce.number().int().min(1).max(65_535).default(443),
  engine: z.enum(["js", "nmap"]).default("js"),
});
const idSchema = z.coerce.number().int().positive();

const configuredRateLimit = Number.parseInt(process.env.SCAN_RATE_LIMIT || "30", 10);
const scanRateLimit = Number.isInteger(configuredRateLimit) && configuredRateLimit > 0
  ? configuredRateLimit
  : 30;
const scanLimiter = createRateLimiter({ windowMs: 60_000, max: scanRateLimit });

function handleRouteError(res: Response, error: unknown, fallback: string): void {
  if (error instanceof z.ZodError) {
    res.status(400).json({ error: "Invalid request data", details: error.errors });
    return;
  }

  if (error instanceof TargetValidationError) {
    res.status(error.statusCode).json({ error: error.message });
    return;
  }

  console.error(fallback, error);
  res.status(500).json({ error: fallback });
}

export async function registerRoutes(app: Express): Promise<Server> {
  app.get("/api/health", (_req, res) => {
    res.json({
      status: "ok",
      version: packageMetadata.version,
      uptimeSeconds: Math.floor(process.uptime()),
    });
  });

  app.delete("/api/certificate-checks", async (_req, res) => {
    try {
      await storage.clearCertificateChecks();
      res.status(204).send();
    } catch (error) {
      handleRouteError(res, error, "Failed to clear certificate checks");
    }
  });

  app.get("/api/certificate-checks", async (_req, res) => {
    try {
      res.json(await storage.getCertificateChecks());
    } catch (error) {
      handleRouteError(res, error, "Failed to fetch certificate checks");
    }
  });

  app.get("/api/certificate-checks/:hostname", async (req, res) => {
    try {
      const hostname = z.string().trim().min(1).max(253).parse(req.params.hostname);
      res.json(await storage.getCertificateChecksByHostname(hostname));
    } catch (error) {
      handleRouteError(res, error, "Failed to fetch certificate checks");
    }
  });

  app.post("/api/certificate-checks", scanLimiter, async (req, res) => {
    try {
      const { hostname, port } = scanRequestSchema.parse(req.body);
      const result = await performCertificateCheck(hostname, port);
      res.status(201).json(await storage.createCertificateCheck(result));
    } catch (error) {
      handleRouteError(res, error, "Failed to perform certificate check");
    }
  });

  app.post("/api/batch-scans", scanLimiter, async (req, res) => {
    try {
      const { name, hosts } = batchScanRequestSchema.parse(req.body);
      const id = randomUUID();
      const batch = await storage.createBatchScan({
        id,
        name,
        status: "pending",
        totalHosts: hosts.length,
        completedHosts: 0,
        failedHosts: 0,
      });

      void processBatchScan(id, hosts).catch(async (error) => {
        console.error("Batch scan failed", error);
        await storage.updateBatchScan(id, { status: "failed", completedAt: new Date() });
      });

      res.status(202).json(batch);
    } catch (error) {
      handleRouteError(res, error, "Failed to start batch scan");
    }
  });

  app.get("/api/batch-scans", async (_req, res) => {
    try {
      res.json(await storage.getBatchScans());
    } catch (error) {
      handleRouteError(res, error, "Failed to fetch batch scans");
    }
  });

  app.get("/api/batch-scans/:id", async (req, res) => {
    try {
      const batch = await storage.getBatchScan(req.params.id);
      if (!batch) {
        res.status(404).json({ error: "Batch scan not found" });
        return;
      }

      const detailedResults = await storage.getCertificateChecksByBatchId(req.params.id);
      res.json({ ...batch, detailedResults });
    } catch (error) {
      handleRouteError(res, error, "Failed to fetch batch scan");
    }
  });

  app.post("/api/scheduled-scans", async (req, res) => {
    try {
      const scan = scheduleScanRequestSchema.parse(req.body);
      const scheduledScan = await storage.createScheduledScan({
        ...scan,
        nextScan: calculateNextScanTime(scan.scheduleType),
      });
      res.status(201).json(scheduledScan);
    } catch (error) {
      handleRouteError(res, error, "Failed to create scheduled scan");
    }
  });

  app.get("/api/scheduled-scans", async (_req, res) => {
    try {
      res.json(await storage.getScheduledScans());
    } catch (error) {
      handleRouteError(res, error, "Failed to fetch scheduled scans");
    }
  });

  app.put("/api/scheduled-scans/:id", async (req, res) => {
    try {
      const id = idSchema.parse(req.params.id);
      const updates = updateScheduledScanSchema.parse(req.body);
      const updated = await storage.updateScheduledScan(id, updates);
      if (!updated) {
        res.status(404).json({ error: "Scheduled scan not found" });
        return;
      }
      res.json(updated);
    } catch (error) {
      handleRouteError(res, error, "Failed to update scheduled scan");
    }
  });

  app.delete("/api/scheduled-scans/:id", async (req, res) => {
    try {
      const id = idSchema.parse(req.params.id);
      if (!(await storage.deleteScheduledScan(id))) {
        res.status(404).json({ error: "Scheduled scan not found" });
        return;
      }
      res.status(204).send();
    } catch (error) {
      handleRouteError(res, error, "Failed to delete scheduled scan");
    }
  });

  app.get("/api/export/csv", async (_req, res) => {
    try {
      const csv = generateCSV(await storage.getCertificateChecks());
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="certificate-checks.csv"');
      res.send(csv);
    } catch (error) {
      handleRouteError(res, error, "Failed to export CSV");
    }
  });

  app.get("/api/export/json", async (_req, res) => {
    try {
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="certificate-checks.json"');
      res.json(await storage.getCertificateChecks());
    } catch (error) {
      handleRouteError(res, error, "Failed to export JSON");
    }
  });

  app.get("/check-cert", scanLimiter, async (req, res) => {
    try {
      const { hostname, port } = scanTargetSchema.parse({
        hostname: req.query.target,
        port: req.query.port,
      });
      res.json(await performCertificateCheckNmap(hostname, port));
    } catch (error) {
      handleRouteError(res, error, "Failed to check certificate");
    }
  });

  app.get("/api/v1/check/:hostname", scanLimiter, async (req, res) => {
    try {
      const { port, engine } = checkQuerySchema.parse(req.query);
      const { hostname } = scanTargetSchema.pick({ hostname: true }).parse(req.params);
      const result = engine === "nmap"
        ? await performCertificateCheckNmap(hostname, port)
        : await performCertificateCheck(hostname, port);

      res.json({ ...result, engine, timestamp: new Date().toISOString() });
    } catch (error) {
      handleRouteError(res, error, "Failed to check certificate");
    }
  });

  app.get("/api/download-script", (_req, res) => {
    res.download(getNseScriptPath(), "tls-expired-cert-checker.nse", (error) => {
      if (error && !res.headersSent) {
        handleRouteError(res, error, "NSE script is unavailable");
      }
    });
  });

  return createServer(app);
}

async function processBatchScan(
  batchId: string,
  hosts: Array<{ hostname: string; port: number }>,
): Promise<void> {
  await storage.updateBatchScan(batchId, { status: "running" });
  let completed = 0;
  let failed = 0;
  const results: InsertCertificateCheck[] = [];

  for (const host of hosts) {
    let result: InsertCertificateCheck;
    try {
      result = await performCertificateCheck(host.hostname, host.port);
    } catch (error) {
      result = {
        hostname: host.hostname,
        port: host.port,
        status: "error",
        errorMessage: error instanceof TargetValidationError
          ? error.message
          : "Failed to scan host",
        daysUntilExpiration: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validUntil: null,
        batchId,
      };
    }

    result = { ...result, batchId };
    await storage.createCertificateCheck(result);
    results.push(result);

    if (result.status === "error") failed += 1;
    else completed += 1;

    await storage.updateBatchScan(batchId, {
      completedHosts: completed,
      failedHosts: failed,
    });
  }

  await storage.updateBatchScan(batchId, {
    status: "completed",
    completedAt: new Date(),
    results,
  });
}

function calculateNextScanTime(scheduleType: "daily" | "weekly" | "monthly"): Date {
  const next = new Date();
  if (scheduleType === "daily") next.setDate(next.getDate() + 1);
  if (scheduleType === "weekly") next.setDate(next.getDate() + 7);
  if (scheduleType === "monthly") next.setMonth(next.getMonth() + 1);
  return next;
}

function escapeCsvField(value: unknown): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function generateCSV(checks: CertificateCheck[]): string {
  const headers = [
    "hostname",
    "port",
    "status",
    "daysUntilExpiration",
    "issuer",
    "subject",
    "validFrom",
    "validUntil",
    "errorMessage",
    "scanTimestamp",
  ];

  const rows = checks.map((check) => [
    check.hostname,
    check.port,
    check.status,
    check.daysUntilExpiration,
    check.issuer,
    check.subject,
    check.validFrom?.toISOString(),
    check.validUntil?.toISOString(),
    check.errorMessage,
    check.scanTimestamp?.toISOString(),
  ]);

  return [headers.map(escapeCsvField).join(","), ...rows.map((row) => row.map(escapeCsvField).join(","))]
    .join("\n");
}
