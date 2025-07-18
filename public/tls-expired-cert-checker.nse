local sslcert = require "sslcert"
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
  
  return table.concat(result, "\n")
end
