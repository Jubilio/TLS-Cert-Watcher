import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Code, Copy } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import SyntaxHighlighter from "@/components/syntax-highlighter";

export default function NSEScript() {
  const { toast } = useToast();

  const nseScript = `local sslcert = require "sslcert"
local shortport = require "shortport"
local stdnse = require "stdnse"
local datetime = require "datetime"

description = [[
Verifica se certificados TLS estão expirados ou próximos da expiração.
]]

author = "Jubilio Mausse"
license = "Same as Nmap"
categories = {"safe", "default", "discovery"}

portrule = shortport.port_or_service(443, "https")

action = function(host, port)
  local cert = sslcert.getCertificate(host, port)
  if not cert or not cert.validity or not cert.validity["notAfter"] then
    return "Certificado não encontrado ou inválido."
  end

  local expiration = cert.validity["notAfter"]
  local now = datetime.new()
  local days_left = (expiration - now):days()

  if days_left < 0 then
    return "❌ Certificado expirado há " .. math.abs(days_left) .. " dias!"
  elseif days_left < 30 then
    return "⚠️ Certificado válido por apenas " .. days_left .. " dias."
  else
    return "✅ Certificado válido por " .. days_left .. " dias."
  end
end`;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(nseScript);
      toast({
        title: "Copied!",
        description: "NSE script copied to clipboard",
      });
    } catch (err) {
      toast({
        title: "Error",
        description: "Failed to copy script to clipboard",
        variant: "destructive",
      });
    }
  };

  return (
    <Card className="bg-slate-800/50 border-slate-700">
      <CardContent className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center">
            <Code className="text-green-400 mr-2" />
            NSE Script Source
          </h3>
          <Button 
            variant="ghost" 
            size="sm"
            onClick={handleCopy}
            className="text-slate-400 hover:text-slate-200 text-sm"
          >
            <Copy className="mr-1 h-4 w-4" />
            Copy
          </Button>
        </div>
        
        <Card className="bg-slate-900 border-slate-600">
          <CardContent className="p-4 overflow-x-auto">
            <SyntaxHighlighter code={nseScript} language="lua" />
          </CardContent>
        </Card>
      </CardContent>
    </Card>
  );
}
