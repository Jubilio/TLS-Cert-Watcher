import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  insertCertificateCheckSchema,
  batchScanRequestSchema,
  scheduleScanRequestSchema
} from "@shared/schema";
import { z } from "zod";
import * as https from "https";
import * as tls from "tls";
import { randomUUID } from "crypto";

export async function registerRoutes(app: Express): Promise<Server> {
  
  // Get all certificate checks
  app.get("/api/certificate-checks", async (req, res) => {
    try {
      const checks = await storage.getCertificateChecks();
      res.json(checks);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch certificate checks" });
    }
  });

  // Get certificate checks for a specific hostname
  app.get("/api/certificate-checks/:hostname", async (req, res) => {
    try {
      const { hostname } = req.params;
      const checks = await storage.getCertificateChecksByHostname(hostname);
      res.json(checks);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch certificate checks" });
    }
  });

  // Perform certificate check
  app.post("/api/certificate-checks", async (req, res) => {
    try {
      const requestSchema = z.object({
        hostname: z.string().min(1),
        port: z.number().optional().default(443)
      });

      const { hostname, port } = requestSchema.parse(req.body);

      // Perform actual certificate check
      const checkResult = await performCertificateCheck(hostname, port);
      
      // Store the result
      const savedCheck = await storage.createCertificateCheck(checkResult);
      
      res.json(savedCheck);
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Invalid request data", details: error.errors });
      } else {
        res.status(500).json({ error: "Failed to perform certificate check" });
      }
    }
  });

  // Batch scan endpoints
  app.post("/api/batch-scans", async (req, res) => {
    try {
      const { name, hosts } = batchScanRequestSchema.parse(req.body);
      const batchId = randomUUID();

      // Create batch scan record
      const batch = await storage.createBatchScan({
        id: batchId,
        name,
        status: 'pending',
        totalHosts: hosts.length,
        completedHosts: 0,
        failedHosts: 0
      });

      // Start batch processing asynchronously
      processBatchScan(batchId, hosts);

      res.json(batch);
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Invalid request data", details: error.errors });
      } else {
        res.status(500).json({ error: "Failed to start batch scan" });
      }
    }
  });

  app.get("/api/batch-scans", async (req, res) => {
    try {
      const batches = await storage.getBatchScans();
      res.json(batches);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch batch scans" });
    }
  });

  app.get("/api/batch-scans/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const batch = await storage.getBatchScan(id);
      if (!batch) {
        return res.status(404).json({ error: "Batch scan not found" });
      }
      
      const results = await storage.getCertificateChecksByBatchId(id);
      res.json({ ...batch, detailedResults: results });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch batch scan" });
    }
  });

  // Scheduled scan endpoints
  app.post("/api/scheduled-scans", async (req, res) => {
    try {
      const scanData = scheduleScanRequestSchema.parse(req.body);
      
      // Calculate next scan time
      const nextScan = calculateNextScanTime(scanData.scheduleType);
      
      const scheduledScan = await storage.createScheduledScan({
        ...scanData,
        nextScan
      });

      res.json(scheduledScan);
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Invalid request data", details: error.errors });
      } else {
        res.status(500).json({ error: "Failed to create scheduled scan" });
      }
    }
  });

  app.get("/api/scheduled-scans", async (req, res) => {
    try {
      const scans = await storage.getScheduledScans();
      res.json(scans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scheduled scans" });
    }
  });

  app.put("/api/scheduled-scans/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      
      const updatedScan = await storage.updateScheduledScan(id, updates);
      if (!updatedScan) {
        return res.status(404).json({ error: "Scheduled scan not found" });
      }
      
      res.json(updatedScan);
    } catch (error) {
      res.status(500).json({ error: "Failed to update scheduled scan" });
    }
  });

  app.delete("/api/scheduled-scans/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteScheduledScan(id);
      
      if (!deleted) {
        return res.status(404).json({ error: "Scheduled scan not found" });
      }
      
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete scheduled scan" });
    }
  });

  // Export endpoints
  app.get("/api/export/csv", async (req, res) => {
    try {
      const checks = await storage.getCertificateChecks();
      const csv = generateCSV(checks);
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="certificate-checks.csv"');
      res.send(csv);
    } catch (error) {
      res.status(500).json({ error: "Failed to export CSV" });
    }
  });

  app.get("/api/export/json", async (req, res) => {
    try {
      const checks = await storage.getCertificateChecks();
      
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="certificate-checks.json"');
      res.json(checks);
    } catch (error) {
      res.status(500).json({ error: "Failed to export JSON" });
    }
  });

  // API for external access
  app.get("/api/v1/check/:hostname", async (req, res) => {
    try {
      const { hostname } = req.params;
      const port = req.query.port ? parseInt(req.query.port as string) : 443;
      
      // Perform certificate check
      const checkResult = await performCertificateCheck(hostname, port);
      
      res.json({
        hostname,
        port,
        status: checkResult.status,
        daysUntilExpiration: checkResult.daysUntilExpiration,
        validUntil: checkResult.validUntil,
        issuer: checkResult.issuer,
        subject: checkResult.subject,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to check certificate" });
    }
  });

  // Download NSE script
  app.get("/api/download-script", (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', 'attachment; filename="tls-expired-cert-checker.nse"');
    
    const nseScript = `local sslcert = require "sslcert"
local shortport = require "shortport"
local stdnse = require "stdnse"
local datetime = require "datetime"

description = [[
Verifica se certificados TLS estão expirados ou próximos da expiração.
Este script conecta-se a serviços HTTPS e analisa a data de validade
dos certificados TLS/SSL, alertando sobre certificados expirados ou
que expirarão em menos de 30 dias.
]]

author = "Jubilio Mausse"
license = "Same as Nmap"
categories = {"safe", "default", "discovery"}

portrule = shortport.port_or_service(443, "https")

local function days_between(date1, date2)
  local diff = os.difftime(date2, date1)
  return math.floor(diff / (24 * 60 * 60))
end

local function parse_cert_date(date_str)
  -- Parse certificate date string to timestamp
  local pattern = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)"
  local year, month, day, hour, min, sec = date_str:match(pattern)
  if year then
    return os.time({
      year = tonumber(year),
      month = tonumber(month),
      day = tonumber(day),
      hour = tonumber(hour),
      min = tonumber(min),
      sec = tonumber(sec)
    })
  end
  return nil
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  
  if not status then
    return "❓ Não foi possível obter o certificado SSL/TLS"
  end
  
  if not cert or not cert.validity or not cert.validity.notAfter then
    return "❓ Certificado não encontrado ou dados de validade inválidos"
  end

  local expiration_time = parse_cert_date(cert.validity.notAfter)
  local current_time = os.time()
  
  if not expiration_time then
    return "❓ Não foi possível analisar a data de expiração do certificado"
  end

  local days_left = days_between(current_time, expiration_time)
  local result = {}
  
  -- Certificate details
  table.insert(result, "Detalhes do Certificado:")
  if cert.subject then
    table.insert(result, "  Subject: " .. (cert.subject.commonName or "N/A"))
  end
  if cert.issuer then
    table.insert(result, "  Issuer: " .. (cert.issuer.commonName or "N/A"))
  end
  table.insert(result, "  Válido até: " .. cert.validity.notAfter)
  
  -- Status based on days left
  if days_left < 0 then
    table.insert(result, "❌ CRÍTICO: Certificado expirado há " .. math.abs(days_left) .. " dias!")
  elseif days_left == 0 then
    table.insert(result, "❌ CRÍTICO: Certificado expira hoje!")
  elseif days_left <= 7 then
    table.insert(result, "🔴 URGENTE: Certificado expira em " .. days_left .. " dias!")
  elseif days_left <= 30 then
    table.insert(result, "⚠️ ATENÇÃO: Certificado expira em " .. days_left .. " dias")
  else
    table.insert(result, "✅ OK: Certificado válido por " .. days_left .. " dias")
  end
  
  return table.concat(result, "\\n")
end`;

    res.send(nseScript);
  });

  const httpServer = createServer(app);
  return httpServer;
}

async function performCertificateCheck(hostname: string, port: number) {
  return new Promise<any>((resolve, reject) => {
    const options = {
      hostname,
      port,
      method: 'HEAD',
      rejectUnauthorized: false, // Allow self-signed certificates
      timeout: 10000
    };

    const req = https.request(options, (res) => {
      const cert = (res.socket as any).getPeerCertificate();
      
      if (!cert || Object.keys(cert).length === 0) {
        resolve({
          hostname,
          port,
          status: 'error',
          errorMessage: 'Certificate not found or invalid',
          daysUntilExpiration: null,
          issuer: null,
          subject: null,
          validFrom: null,
          validUntil: null
        });
        return;
      }

      const now = new Date();
      const validUntil = new Date(cert.valid_to);
      const validFrom = new Date(cert.valid_from);
      const msPerDay = 24 * 60 * 60 * 1000;
      const daysUntilExpiration = Math.floor((validUntil.getTime() - now.getTime()) / msPerDay);

      let status: string;
      if (daysUntilExpiration < 0) {
        status = 'expired';
      } else if (daysUntilExpiration <= 30) {
        status = 'warning';
      } else {
        status = 'valid';
      }

      resolve({
        hostname,
        port,
        status,
        daysUntilExpiration,
        issuer: cert.issuer?.CN || cert.issuer?.O || 'Unknown',
        subject: cert.subject?.CN || cert.subject?.O || 'Unknown', 
        validFrom,
        validUntil,
        errorMessage: null
      });
    });

    req.on('error', (error) => {
      resolve({
        hostname,
        port,
        status: 'error',
        errorMessage: error.message,
        daysUntilExpiration: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validUntil: null
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        hostname,
        port,
        status: 'error',
        errorMessage: 'Connection timeout',
        daysUntilExpiration: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validUntil: null
      });
    });

    req.end();
  });
}

// Helper functions
async function processBatchScan(batchId: string, hosts: Array<{hostname: string, port: number}>) {
  await storage.updateBatchScan(batchId, { status: 'running' });
  
  let completed = 0;
  let failed = 0;
  
  const results = [];
  
  for (const host of hosts) {
    try {
      const result = await performCertificateCheck(host.hostname, host.port);
      
      // Store individual check result
      await storage.createCertificateCheck({
        ...result,
        batchId
      });
      
      results.push(result);
      completed++;
    } catch (error) {
      failed++;
      results.push({
        hostname: host.hostname,
        port: host.port,
        status: 'error',
        errorMessage: 'Failed to scan host',
        daysUntilExpiration: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validUntil: null
      });
    }
    
    // Update progress
    await storage.updateBatchScan(batchId, {
      completedHosts: completed,
      failedHosts: failed
    });
  }
  
  // Mark as completed
  await storage.updateBatchScan(batchId, {
    status: 'completed',
    completedAt: new Date(),
    results: results
  });
}

function calculateNextScanTime(scheduleType: string): Date {
  const now = new Date();
  const next = new Date(now);
  
  switch (scheduleType) {
    case 'daily':
      next.setDate(next.getDate() + 1);
      break;
    case 'weekly':
      next.setDate(next.getDate() + 7);
      break;
    case 'monthly':
      next.setMonth(next.getMonth() + 1);
      break;
    default:
      next.setDate(next.getDate() + 1);
  }
  
  return next;
}

function generateCSV(checks: any[]): string {
  const headers = [
    'hostname', 'port', 'status', 'daysUntilExpiration', 
    'issuer', 'subject', 'validFrom', 'validUntil', 
    'errorMessage', 'scanTimestamp'
  ];
  
  const rows = checks.map(check => [
    check.hostname,
    check.port,
    check.status,
    check.daysUntilExpiration || '',
    check.issuer || '',
    check.subject || '',
    check.validFrom || '',
    check.validUntil || '',
    check.errorMessage || '',
    check.scanTimestamp || ''
  ]);
  
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
  ].join('\n');
  
  return csvContent;
}
