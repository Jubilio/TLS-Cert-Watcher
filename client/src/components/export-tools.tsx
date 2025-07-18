import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Download, FileText, Database, Code } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import type { CertificateCheck } from "@shared/schema";

export default function ExportTools() {
  const { toast } = useToast();

  const { data: checks, isLoading } = useQuery<CertificateCheck[]>({
    queryKey: ["/api/certificate-checks"],
  });

  const handleExportCSV = () => {
    window.open('/api/export/csv', '_blank');
    toast({
      title: "Export Started",
      description: "CSV file download should begin shortly",
    });
  };

  const handleExportJSON = () => {
    window.open('/api/export/json', '_blank');
    toast({
      title: "Export Started", 
      description: "JSON file download should begin shortly",
    });
  };

  const generateAPIExample = () => {
    const baseUrl = window.location.origin;
    return `# TLS Certificate Checker API Examples

## Check single certificate
curl "${baseUrl}/api/v1/check/google.com"

## Check with custom port  
curl "${baseUrl}/api/v1/check/example.com?port=8443"

## Response format
{
  "hostname": "google.com",
  "port": 443,
  "status": "valid",
  "daysUntilExpiration": 89,
  "validUntil": "2024-04-15T12:00:00Z",
  "issuer": "Google Trust Services LLC",
  "subject": "*.google.com",
  "timestamp": "2024-01-15T12:00:00Z"
}`;
  };

  const copyAPIExample = async () => {
    try {
      await navigator.clipboard.writeText(generateAPIExample());
      toast({
        title: "Copied",
        description: "API examples copied to clipboard",
      });
    } catch (err) {
      toast({
        title: "Error",
        description: "Failed to copy to clipboard",
        variant: "destructive",
      });
    }
  };

  const totalChecks = checks?.length || 0;
  const validCerts = checks?.filter(c => c.status === 'valid').length || 0;
  const expiringSoon = checks?.filter(c => c.status === 'warning').length || 0;
  const expired = checks?.filter(c => c.status === 'expired').length || 0;

  return (
    <div className="space-y-6">
      {/* Export Data */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <Download className="text-green-400 mr-2" />
            Export Certificate Data
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-700/50 rounded-lg p-4">
              <h3 className="font-semibold text-slate-200 mb-2">Summary Statistics</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">Total Checks:</span>
                  <span className="text-slate-200">{totalChecks}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-green-400">Valid Certificates:</span>
                  <span className="text-green-400">{validCerts}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-yellow-400">Expiring Soon:</span>
                  <span className="text-yellow-400">{expiringSoon}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-red-400">Expired:</span>
                  <span className="text-red-400">{expired}</span>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold text-slate-200">Export Formats</h3>
              
              <Button
                onClick={handleExportCSV}
                disabled={isLoading || totalChecks === 0}
                className="w-full bg-green-600 hover:bg-green-700 justify-start"
              >
                <FileText className="w-4 h-4 mr-2" />
                Export as CSV
              </Button>
              
              <Button
                onClick={handleExportJSON}
                disabled={isLoading || totalChecks === 0}
                className="w-full bg-blue-600 hover:bg-blue-700 justify-start"
              >
                <Database className="w-4 h-4 mr-2" />
                Export as JSON
              </Button>

              {totalChecks === 0 && (
                <p className="text-sm text-slate-400 mt-2">
                  No certificate data available for export. Run some scans first.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* API Access */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <Code className="text-purple-400 mr-2" />
            REST API Access
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-slate-300">
            Use our REST API to programmatically check certificates and integrate 
            with your monitoring systems.
          </p>

          <div className="bg-slate-900 border border-slate-600 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="font-semibold text-slate-200">API Endpoint</h4>
              <Button
                variant="ghost"
                size="sm"
                onClick={copyAPIExample}
                className="text-slate-400 hover:text-slate-200"
              >
                Copy Examples
              </Button>
            </div>
            <pre className="text-sm text-slate-300 whitespace-pre-wrap">
              <code>{`GET ${window.location.origin}/api/v1/check/:hostname`}</code>
            </pre>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <h4 className="font-semibold text-slate-200 mb-2">Parameters</h4>
              <ul className="space-y-1 text-slate-400">
                <li><code className="text-blue-300">hostname</code> - Domain or IP to check</li>
                <li><code className="text-blue-300">port</code> - Optional, defaults to 443</li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-200 mb-2">Response Status</h4>
              <ul className="space-y-1 text-slate-400">
                <li><span className="text-green-400">valid</span> - Certificate is valid</li>
                <li><span className="text-yellow-400">warning</span> - Expires within 30 days</li>
                <li><span className="text-red-400">expired</span> - Certificate has expired</li>
                <li><span className="text-slate-400">error</span> - Connection/scan error</li>
              </ul>
            </div>
          </div>

          <div className="bg-slate-700/50 rounded-lg p-4">
            <h4 className="font-semibold text-slate-200 mb-2">Example Usage</h4>
            <div className="space-y-2 text-sm">
              <div>
                <span className="text-slate-400">Python:</span>
                <code className="block text-blue-300 mt-1">
                  {`import requests; r = requests.get('${window.location.origin}/api/v1/check/google.com')`}
                </code>
              </div>
              <div>
                <span className="text-slate-400">JavaScript:</span>
                <code className="block text-blue-300 mt-1">
                  {`fetch('${window.location.origin}/api/v1/check/google.com').then(r => r.json())`}
                </code>
              </div>
            </div>
          </div>

          <div className="text-xs text-slate-500 bg-slate-700/30 rounded p-3">
            <strong>Note:</strong> The API is rate-limited to prevent abuse. For high-volume usage, 
            consider using the batch scanning feature or implementing appropriate delays between requests.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}