import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { PlayCircle, Clock, Search } from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { CertificateCheck } from "@shared/schema";

export default function CertificateTester() {
  const [hostname, setHostname] = useState("");
  const [useCustomPort, setUseCustomPort] = useState(false);
  const [customPort, setCustomPort] = useState("443");
  const { toast } = useToast();

  const { data: recentChecks, isLoading: isLoadingChecks } = useQuery<CertificateCheck[]>({
    queryKey: ["/api/certificate-checks"],
  });

  const checkCertificateMutation = useMutation({
    mutationFn: async (data: { hostname: string; port: number }) => {
      const response = await apiRequest("POST", "/api/certificate-checks", data);
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/certificate-checks"] });
      
      let message = "";
      let variant: "default" | "destructive" = "default";
      
      if (data.status === "expired") {
        message = `Certificate expired ${Math.abs(data.daysUntilExpiration)} days ago!`;
        variant = "destructive";
      } else if (data.status === "warning") {
        message = `Certificate expires in ${data.daysUntilExpiration} days`;
        variant = "destructive";
      } else if (data.status === "valid") {
        message = `Certificate is valid for ${data.daysUntilExpiration} days`;
      } else {
        message = data.errorMessage || "Error checking certificate";
        variant = "destructive";
      }
      
      toast({
        title: "Certificate Check Complete",
        description: message,
        variant,
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to check certificate",
        variant: "destructive",
      });
    },
  });

  const handleScan = () => {
    if (!hostname.trim()) {
      toast({
        title: "Error",
        description: "Please enter a hostname",
        variant: "destructive",
      });
      return;
    }

    const port = useCustomPort ? parseInt(customPort) : 443;
    checkCertificateMutation.mutate({ hostname: hostname.trim(), port });
  };

  const formatScanResult = (check: CertificateCheck) => {
    const lines = [];
    lines.push(`Starting TLS certificate scan for ${check.hostname}:${check.port}...`);
    lines.push(`Connecting to ${check.hostname}:${check.port}...`);
    
    if (check.status === "error") {
      lines.push(`❌ Error: ${check.errorMessage}`);
    } else {
      lines.push("✅ Certificate found and extracted");
      lines.push("Certificate Details:");
      lines.push(`  Subject: ${check.subject || "Unknown"}`);
      lines.push(`  Issuer: ${check.issuer || "Unknown"}`);
      if (check.validFrom) {
        lines.push(`  Valid From: ${new Date(check.validFrom).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC')}`);
      }
      if (check.validUntil) {
        lines.push(`  Valid Until: ${new Date(check.validUntil).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC')}`);
      }
      
      if (check.status === "expired") {
        lines.push(`❌ Certificate expired ${Math.abs(check.daysUntilExpiration || 0)} days ago!`);
      } else if (check.status === "warning") {
        lines.push(`⚠️ Certificate valid for only ${check.daysUntilExpiration} days.`);
      } else {
        lines.push(`✅ Certificate valid for ${check.daysUntilExpiration} days.`);
      }
    }
    
    lines.push("Scan completed");
    return lines;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "valid": return "text-emerald-300";
      case "warning": return "text-amber-300";
      case "expired": return "text-red-300";
      default: return "text-slate-400";
    }
  };

  const latestCheck = recentChecks?.[0];

  return (
    <Card className="bg-slate-800/50 border-slate-700">
      <CardContent className="p-6">
        <h2 className="text-xl font-semibold mb-6 flex items-center">
          <PlayCircle className="text-blue-400 mr-2" />
          Test Certificate Checker
        </h2>
        
        {/* Input Form */}
        <div className="space-y-4 mb-6">
          <div>
            <Label className="block text-sm font-medium text-slate-300 mb-2">Target Host</Label>
            <div className="flex space-x-3">
              <Input
                type="text"
                placeholder="example.com or 192.168.1.1"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="flex-1 bg-slate-700 border-slate-600 text-slate-50 placeholder-slate-400 focus:border-blue-400 focus:ring-blue-400"
                disabled={checkCertificateMutation.isPending}
              />
              <Button 
                onClick={handleScan}
                disabled={checkCertificateMutation.isPending}
                className="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2"
              >
                <Search className="mr-2 h-4 w-4" />
                {checkCertificateMutation.isPending ? "Scanning..." : "Scan"}
              </Button>
            </div>
          </div>
          
          <div className="flex items-center space-x-4 text-sm text-slate-400">
            <label className="flex items-center space-x-2">
              <Checkbox 
                checked={!useCustomPort} 
                onCheckedChange={() => setUseCustomPort(false)}
                className="text-blue-500 bg-slate-700 border-slate-600"
              />
              <span>Port 443 (HTTPS)</span>
            </label>
            <label className="flex items-center space-x-2">
              <Checkbox 
                checked={useCustomPort} 
                onCheckedChange={(checked) => setUseCustomPort(checked as boolean)}
                className="text-blue-500 bg-slate-700 border-slate-600"
              />
              <span>Custom port</span>
            </label>
            {useCustomPort && (
              <Input
                type="number"
                value={customPort}
                onChange={(e) => setCustomPort(e.target.value)}
                className="w-20 bg-slate-700 border-slate-600 text-slate-50"
                min="1"
                max="65535"
              />
            )}
          </div>
        </div>

        {/* Results Area */}
        <Card className="bg-slate-900 border-slate-600 min-h-[300px]">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-slate-200">Scan Results</h3>
              {latestCheck && (
                <div className="flex items-center space-x-2 text-sm text-slate-400">
                  <Clock className="h-4 w-4" />
                  <span>Last scan: {new Date(latestCheck.scanTimestamp!).toLocaleString()}</span>
                </div>
              )}
              <Button variant="ghost" size="sm" onClick={async () => {
                await apiRequest("DELETE", "/api/certificate-checks");
                queryClient.invalidateQueries({ queryKey: ["/api/certificate-checks"] });
              }}>
                Clear
              </Button>
            </div>

            {checkCertificateMutation.isPending && (
              <div className="flex items-center justify-center py-16">
                <div className="text-center">
                  <div className="animate-pulse text-blue-400 text-2xl mb-2">
                    <Search className="h-8 w-8 mx-auto" />
                  </div>
                  <div className="text-slate-300">Scanning certificate...</div>
                </div>
              </div>
            )}

            {!checkCertificateMutation.isPending && latestCheck && (
              <div className="space-y-1 font-mono text-sm">
                {formatScanResult(latestCheck).map((line, index) => (
                  <div 
                    key={index} 
                    className={`${
                      line.includes("❌") ? "text-red-300 font-medium" :
                      line.includes("⚠️") ? "text-amber-300 font-medium" :
                      line.includes("✅") ? "text-emerald-300" :
                      line.includes("Connecting") || line.includes("Starting") ? "text-blue-300" :
                      line.includes("Certificate Details:") ? "text-slate-300" :
                      line.startsWith("  ") ? "text-slate-400 ml-4" :
                      "text-slate-400"
                    }`}
                  >
                    {line}
                  </div>
                ))}
              </div>
            )}

            {!checkCertificateMutation.isPending && !latestCheck && (
              <div className="flex items-center justify-center py-16 text-slate-400">
                <div className="text-center">
                  <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <div>Enter a hostname and click Scan to test certificate expiration</div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </CardContent>
    </Card>
  );
}
