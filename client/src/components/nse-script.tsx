import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Code, Copy } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import SyntaxHighlighter from "@/components/syntax-highlighter";

export default function NSEScript() {
  const { toast } = useToast();
  const { data: nseScript = "", isLoading, error } = useQuery<string>({
    queryKey: ["nse-script-source"],
    queryFn: async () => {
      const response = await fetch("/api/download-script");
      if (!response.ok) throw new Error("Failed to load the NSE script");
      return response.text();
    },
    staleTime: Infinity,
  });

  const handleCopy = async () => {
    if (!nseScript) return;
    try {
      await navigator.clipboard.writeText(nseScript);
      toast({
        title: "Copied!",
        description: "NSE script copied to clipboard",
      });
    } catch {
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
            disabled={isLoading || !nseScript}
            className="text-slate-400 hover:text-slate-200 text-sm"
          >
            <Copy className="mr-1 h-4 w-4" />
            Copy
          </Button>
        </div>

        <Card className="bg-slate-900 border-slate-600">
          <CardContent className="p-4 overflow-x-auto">
            {isLoading && <p className="text-slate-400">Loading script…</p>}
            {error && <p className="text-red-300">The NSE script could not be loaded.</p>}
            {nseScript && <SyntaxHighlighter code={nseScript} language="lua" />}
          </CardContent>
        </Card>
      </CardContent>
    </Card>
  );
}
