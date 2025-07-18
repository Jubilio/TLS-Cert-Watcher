import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Calendar, Clock, Mail, Webhook, Plus, Trash2, Edit3 } from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { ScheduledScan } from "@shared/schema";

export default function ScheduledScans() {
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    hostname: "",
    port: 443,
    scheduleType: "weekly" as "daily" | "weekly" | "monthly",
    notifyEmail: "",
    notifyWebhook: ""
  });
  
  const { toast } = useToast();

  const { data: scans, isLoading } = useQuery<ScheduledScan[]>({
    queryKey: ["/api/scheduled-scans"],
  });

  const createScanMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const payload = {
        ...data,
        notifyEmail: data.notifyEmail || undefined,
        notifyWebhook: data.notifyWebhook || undefined
      };
      const response = await apiRequest("POST", "/api/scheduled-scans", payload);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      setShowForm(false);
      setFormData({
        hostname: "",
        port: 443,
        scheduleType: "weekly",
        notifyEmail: "",
        notifyWebhook: ""
      });
      toast({
        title: "Scheduled Scan Created",
        description: "Certificate monitoring has been set up successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to create scheduled scan",
        variant: "destructive",
      });
    },
  });

  const toggleScanMutation = useMutation({
    mutationFn: async ({ id, isActive }: { id: number; isActive: boolean }) => {
      const response = await apiRequest("PUT", `/api/scheduled-scans/${id}`, { isActive });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      toast({
        title: "Scan Updated",
        description: "Scheduled scan status has been changed",
      });
    },
  });

  const deleteScanMutation = useMutation({
    mutationFn: async (id: number) => {
      const response = await apiRequest("DELETE", `/api/scheduled-scans/${id}`, {});
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      toast({
        title: "Scan Deleted",
        description: "Scheduled scan has been removed",
      });
    },
  });

  const handleSubmit = () => {
    if (!formData.hostname.trim()) {
      toast({
        title: "Error",
        description: "Please enter a hostname",
        variant: "destructive",
      });
      return;
    }
    createScanMutation.mutate(formData);
  };

  const getScheduleDescription = (type: string) => {
    switch (type) {
      case 'daily': return 'Every day';
      case 'weekly': return 'Every week';
      case 'monthly': return 'Every month';
      default: return 'Unknown';
    }
  };

  const getScheduleColor = (type: string) => {
    switch (type) {
      case 'daily': return 'bg-blue-500';
      case 'weekly': return 'bg-green-500';
      case 'monthly': return 'bg-purple-500';
      default: return 'bg-gray-500';
    }
  };

  const formatNextScan = (date: string | Date) => {
    const nextScan = new Date(date);
    const now = new Date();
    const diffHours = Math.ceil((nextScan.getTime() - now.getTime()) / (1000 * 60 * 60));
    
    if (diffHours < 24) {
      return `in ${diffHours}h`;
    } else {
      const diffDays = Math.ceil(diffHours / 24);
      return `in ${diffDays}d`;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center text-xl">
              <Calendar className="text-blue-400 mr-2" />
              Scheduled Certificate Monitoring
            </CardTitle>
            <Button
              onClick={() => setShowForm(!showForm)}
              className="bg-blue-500 hover:bg-blue-600"
            >
              <Plus className="w-4 h-4 mr-2" />
              Schedule Scan
            </Button>
          </div>
        </CardHeader>

        {showForm && (
          <CardContent className="border-t border-slate-700 pt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label className="text-slate-300">Hostname</Label>
                <Input
                  value={formData.hostname}
                  onChange={(e) => setFormData(prev => ({ ...prev, hostname: e.target.value }))}
                  placeholder="example.com"
                  className="bg-slate-700 border-slate-600 text-slate-50"
                />
              </div>
              
              <div>
                <Label className="text-slate-300">Port</Label>
                <Input
                  type="number"
                  value={formData.port}
                  onChange={(e) => setFormData(prev => ({ ...prev, port: parseInt(e.target.value) }))}
                  placeholder="443"
                  className="bg-slate-700 border-slate-600 text-slate-50"
                />
              </div>

              <div>
                <Label className="text-slate-300">Schedule</Label>
                <Select
                  value={formData.scheduleType}
                  onValueChange={(value) => setFormData(prev => ({ ...prev, scheduleType: value as any }))}
                >
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-slate-50">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label className="text-slate-300">Notification Email (Optional)</Label>
                <Input
                  type="email"
                  value={formData.notifyEmail}
                  onChange={(e) => setFormData(prev => ({ ...prev, notifyEmail: e.target.value }))}
                  placeholder="alerts@company.com"
                  className="bg-slate-700 border-slate-600 text-slate-50"
                />
              </div>

              <div className="md:col-span-2">
                <Label className="text-slate-300">Webhook URL (Optional)</Label>
                <Input
                  value={formData.notifyWebhook}
                  onChange={(e) => setFormData(prev => ({ ...prev, notifyWebhook: e.target.value }))}
                  placeholder="https://api.company.com/webhooks/cert-alerts"
                  className="bg-slate-700 border-slate-600 text-slate-50"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2 mt-6">
              <Button
                variant="outline"
                onClick={() => setShowForm(false)}
                className="border-slate-600 text-slate-400 hover:text-slate-200"
              >
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={createScanMutation.isPending}
                className="bg-blue-500 hover:bg-blue-600"
              >
                {createScanMutation.isPending ? "Creating..." : "Create Schedule"}
              </Button>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Scheduled Scans List */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-xl">Active Schedules</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-slate-400">Loading schedules...</div>
          ) : !scans || scans.length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              <Calendar className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No scheduled scans yet</p>
              <p className="text-sm">Create your first scheduled scan to monitor certificates automatically</p>
            </div>
          ) : (
            <div className="space-y-4">
              {scans.map((scan) => (
                <div key={scan.id} className="border border-slate-600 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div>
                        <h3 className="font-semibold text-slate-200">
                          {scan.hostname}:{scan.port}
                        </h3>
                        <div className="flex items-center space-x-2 mt-1">
                          <Badge className={`${getScheduleColor(scan.scheduleType)} text-white`}>
                            {getScheduleDescription(scan.scheduleType)}
                          </Badge>
                          {!scan.isActive && (
                            <Badge variant="outline" className="text-slate-400 border-slate-600">
                              Paused
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center space-x-4">
                      <div className="text-sm text-slate-400 text-right">
                        <div className="flex items-center">
                          <Clock className="w-4 h-4 mr-1" />
                          Next: {formatNextScan(scan.nextScan)}
                        </div>
                        {scan.lastScanned && (
                          <div className="text-xs">
                            Last: {new Date(scan.lastScanned).toLocaleDateString()}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={scan.isActive}
                          onCheckedChange={(checked) => 
                            toggleScanMutation.mutate({ id: scan.id, isActive: checked })
                          }
                          className="data-[state=checked]:bg-blue-500"
                        />
                        
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteScanMutation.mutate(scan.id)}
                          className="text-slate-400 hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </div>

                  {(scan.notifyEmail || scan.notifyWebhook) && (
                    <div className="mt-3 pt-3 border-t border-slate-700">
                      <div className="flex items-center space-x-4 text-sm text-slate-400">
                        {scan.notifyEmail && (
                          <div className="flex items-center">
                            <Mail className="w-4 h-4 mr-1" />
                            {scan.notifyEmail}
                          </div>
                        )}
                        {scan.notifyWebhook && (
                          <div className="flex items-center">
                            <Webhook className="w-4 h-4 mr-1" />
                            Webhook configured
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}