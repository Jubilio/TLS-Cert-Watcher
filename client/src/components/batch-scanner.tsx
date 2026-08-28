import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Upload, FileText, Download } from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { BatchScan } from "@shared/schema";

export default function BatchScanner() {
  const [batchName, setBatchName] = useState("");
  const [hostsText, setHostsText] = useState("");
  const { toast } = useToast();

  const { data: batches, isLoading: isLoadingBatches } = useQuery<BatchScan[]>({
    queryKey: ["/api/batch-scans"],
  });

  const startBatchScanMutation = useMutation({
    mutationFn: async (data: { name: string; hosts: Array<{hostname: string, port: number}> }) => {
      const response = await apiRequest("POST", "/api/batch-scans", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/batch-scans"] });
      setBatchName("");
      setHostsText("");
      toast({
        title: "Batch Scan Started",
        description: "Your batch scan has been queued for processing",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to start batch scan",
        variant: "destructive",
      });
    },
  });

  const handleStartBatchScan = () => {
    if (!batchName.trim() || !hostsText.trim()) {
      toast({
        title: "Error",
        description: "Please provide a batch name and hosts list",
        variant: "destructive",
      });
      return;
    }

    // Parse hosts from text input
    const lines = hostsText.split('\n').filter(line => line.trim());
    const hosts = lines.map(line => {
      let raw = line.trim();
      let parsedHostname = raw;
      let parsedPort = 443;

      // If it looks like a URL, extract hostname and port using URL API
      if (raw.startsWith("http://") || raw.startsWith("https://")) {
        try {
          const url = new URL(raw);
          parsedHostname = url.hostname;
          if (url.port) {
            parsedPort = parseInt(url.port, 10);
          }
        } catch (e) {
          // Fallback if URL parsing fails
          const withoutProtocol = raw.replace(/^https?:\/\//i, "");
          const [hostPart] = withoutProtocol.split('/');
          const parts = hostPart.split(':');
          parsedHostname = parts[0];
          if (parts[1]) parsedPort = parseInt(parts[1], 10);
        }
      } else {
        // Standard hostname or IP, possibly with port (e.g., example.com:8443)
        // Note: IPv6 addresses contain colons, but URL parsing is needed for them if they have ports.
        // For simplicity, we assume standard format or IPv4 with port.
        const lastColonIdx = raw.lastIndexOf(':');
        // Check if it's an IPv6 address without port (has multiple colons, no brackets)
        const isIpv6WithoutPort = raw.split(':').length > 2 && !raw.includes(']');
        
        if (lastColonIdx !== -1 && !isIpv6WithoutPort) {
          // Check if it's an IPv6 with port like [::1]:8443
          if (raw.includes(']')) {
             const bracketEnd = raw.indexOf(']');
             if (lastColonIdx > bracketEnd) {
               parsedHostname = raw.slice(0, bracketEnd + 1);
               parsedPort = parseInt(raw.slice(lastColonIdx + 1), 10);
             } else {
               parsedHostname = raw;
             }
          } else {
            parsedHostname = raw.slice(0, lastColonIdx);
            parsedPort = parseInt(raw.slice(lastColonIdx + 1), 10);
          }
        } else {
          parsedHostname = raw;
        }
      }

      // Cleanup paths if they still exist (e.g., example.com/path)
      if (parsedHostname.includes('/')) {
        parsedHostname = parsedHostname.split('/')[0];
      }

      return { 
        hostname: parsedHostname.trim(), 
        port: Number.isNaN(parsedPort) ? 443 : parsedPort 
      };
    }).filter(host => host.hostname);

    if (hosts.length === 0) {
      toast({
        title: "Error",
        description: "No valid hosts found in the list",
        variant: "destructive",
      });
      return;
    }

    startBatchScanMutation.mutate({ name: batchName, hosts });
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (file.name.endsWith('.csv')) {
        // Parse CSV - assume hostname in first column, port in second (optional)
        const lines = content.split('\n').slice(1); // Skip header
        const hosts = lines.map(line => {
          const [hostname, port] = line.split(',');
          return `${hostname.trim()}${port ? ':' + port.trim() : ''}`;
        }).join('\n');
        setHostsText(hosts);
      } else {
        // Plain text file
        setHostsText(content);
      }
    };
    reader.readAsText(file);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500';
      case 'running': return 'bg-blue-500';
      case 'pending': return 'bg-yellow-500';
      case 'failed': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getProgress = (batch: BatchScan) => {
    if (batch.totalHosts === 0) return 0;
    return ((batch.completedHosts + batch.failedHosts) / batch.totalHosts) * 100;
  };

  return (
    <div className="space-y-6">
      {/* Batch Scanner Form */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <Upload className="text-purple-400 mr-2" />
            Batch Certificate Scanner
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-slate-300">Batch Name</Label>
            <Input
              value={batchName}
              onChange={(e) => setBatchName(e.target.value)}
              placeholder="e.g., Production Servers Q1 2024"
              className="bg-slate-700 border-slate-600 text-slate-50"
              disabled={startBatchScanMutation.isPending}
            />
          </div>

          <div>
            <Label className="text-slate-300">Hosts List</Label>
            <Textarea
              value={hostsText}
              onChange={(e) => setHostsText(e.target.value)}
              placeholder={`Enter one host per line:
example.com
api.example.com:8443
1.1.1.1:443`}
              className="bg-slate-700 border-slate-600 text-slate-50 h-32"
              disabled={startBatchScanMutation.isPending}
            />
            <div className="flex items-center justify-between mt-2">
              <div className="flex items-center space-x-2">
                <input
                  type="file"
                  accept=".txt,.csv"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="file-upload"
                />
                <Button
                  variant="outline"
                  size="sm"
                  asChild
                  className="text-slate-400 border-slate-600 hover:text-slate-200"
                >
                  <label htmlFor="file-upload" className="cursor-pointer">
                    <FileText className="w-4 h-4 mr-1" />
                    Upload File
                  </label>
                </Button>
              </div>
              <span className="text-sm text-slate-400">
                {hostsText.split('\n').filter(line => line.trim()).length} hosts
              </span>
            </div>
          </div>

          <Button
            onClick={handleStartBatchScan}
            disabled={startBatchScanMutation.isPending}
            className="w-full bg-purple-500 hover:bg-purple-600"
          >
            {startBatchScanMutation.isPending ? "Starting Batch Scan..." : "Start Batch Scan"}
          </Button>
        </CardContent>
      </Card>

      {/* Batch History */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-xl">Batch Scan History</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoadingBatches ? (
            <div className="text-center py-8 text-slate-400">Loading batches...</div>
          ) : !batches || batches.length === 0 ? (
            <div className="text-center py-8 text-slate-400">No batch scans yet</div>
          ) : (
            <div className="space-y-4">
              {batches.map((batch) => (
                <div key={batch.id} className="border border-slate-600 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <h3 className="font-semibold text-slate-200">{batch.name}</h3>
                      <Badge className={`${getStatusColor(batch.status)} text-white`}>
                        {batch.status}
                      </Badge>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => window.open(`/api/batch-scans/${batch.id}`, '_blank')}
                        className="text-slate-400 hover:text-slate-200"
                        aria-label={`Open results for ${batch.name}`}
                      >
                        <Download className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm text-slate-400">
                      <span>Progress: {batch.completedHosts + batch.failedHosts} / {batch.totalHosts}</span>
                      <span>{Math.round(getProgress(batch))}%</span>
                    </div>
                    <Progress value={getProgress(batch)} className="h-2" />
                    
                    <div className="flex justify-between text-xs text-slate-500">
                      <span>Created: {new Date(batch.createdAt!).toLocaleString()}</span>
                      {batch.completedAt && (
                        <span>Completed: {new Date(batch.completedAt).toLocaleString()}</span>
                      )}
                    </div>

                    {batch.status === 'completed' && (
                      <div className="flex space-x-4 text-sm text-slate-400">
                        <span className="text-green-400">✓ {batch.completedHosts} successful</span>
                        {batch.failedHosts > 0 && (
                          <span className="text-red-400">✗ {batch.failedHosts} failed</span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
