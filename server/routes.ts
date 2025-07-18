import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertCertificateCheckSchema } from "@shared/schema";
import { z } from "zod";
import * as https from "https";
import * as tls from "tls";

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
      const cert = res.socket.getPeerCertificate();
      
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
