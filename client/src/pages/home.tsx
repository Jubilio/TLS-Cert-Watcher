import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Shield, Github, Download, Search, Upload, Calendar, 
  Code, Star, Info, Terminal, List, Database 
} from "lucide-react";
import CertificateTester from "@/components/certificate-tester";
import BatchScanner from "@/components/batch-scanner";
import ScheduledScans from "@/components/scheduled-scans";
import ExportTools from "@/components/export-tools";
import NSEScript from "@/components/nse-script";
import MobileNav from "@/components/mobile-nav";

export default function Home() {
  const [activeSection, setActiveSection] = useState("scanner");

  const handleDownloadScript = () => {
    window.open('/api/download-script', '_blank');
  };

  return (
    <div className="bg-slate-900 text-slate-50 font-sans min-h-screen">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-800/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <MobileNav activeSection={activeSection} onSectionChange={setActiveSection} />
              <div className="flex items-center space-x-2">
                <Shield className="text-blue-400 text-xl" />
                <h1 className="text-xl font-semibold text-slate-50">TLS Cert Checker</h1>
              </div>
              <span className="bg-blue-500/20 text-blue-300 px-2 py-1 rounded text-sm font-mono hidden sm:inline">NSE Script</span>
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="ghost" size="sm" className="text-slate-300 hover:text-slate-50 hidden sm:flex">
                <Github className="text-lg" />
              </Button>
              <Button 
                variant="ghost" 
                size="sm" 
                className="text-slate-300 hover:text-slate-50"
                onClick={handleDownloadScript}
              >
                <Download className="text-lg" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex flex-col lg:flex-row gap-8">
          {/* Desktop Sidebar */}
          <aside className="hidden lg:block lg:w-80 space-y-6">
            {/* Script Overview */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Info className="text-blue-400 mr-2" />
                  Script Overview
                </h2>
                <div className="space-y-3 text-sm text-slate-300">
                  <div>
                    <span className="text-slate-400">Filename:</span>
                    <span className="font-mono ml-2">tls-expired-cert-checker.nse</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Author:</span>
                    <span className="ml-2">Jubilio Mausse</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Categories:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      <span className="bg-emerald-500/20 text-emerald-300 px-2 py-1 rounded text-xs">safe</span>
                      <span className="bg-blue-500/20 text-blue-300 px-2 py-1 rounded text-xs">default</span>
                      <span className="bg-purple-500/20 text-purple-300 px-2 py-1 rounded text-xs">discovery</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* New Features */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <Star className="text-amber-400 mr-2" />
                  Enhanced Features
                </h3>
                <ul className="space-y-2 text-sm text-slate-300">
                  <li className="flex items-start">
                    <span className="text-emerald-400 mt-0.5 mr-2 flex-shrink-0">✓</span>
                    Batch certificate scanning
                  </li>
                  <li className="flex items-start">
                    <span className="text-emerald-400 mt-0.5 mr-2 flex-shrink-0">✓</span>
                    Automated scheduled monitoring
                  </li>
                  <li className="flex items-start">
                    <span className="text-emerald-400 mt-0.5 mr-2 flex-shrink-0">✓</span>
                    Export data as CSV/JSON
                  </li>
                  <li className="flex items-start">
                    <span className="text-emerald-400 mt-0.5 mr-2 flex-shrink-0">✓</span>
                    REST API for programmatic access
                  </li>
                  <li className="flex items-start">
                    <span className="text-emerald-400 mt-0.5 mr-2 flex-shrink-0">✓</span>
                    Mobile-responsive interface
                  </li>
                  <li className="flex items-start">
                    <span className="text-emerald-400 mt-0.5 mr-2 flex-shrink-0">✓</span>
                    Email & webhook notifications
                  </li>
                </ul>
              </CardContent>
            </Card>

            {/* Usage Example */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <Terminal className="text-green-400 mr-2" />
                  Usage
                </h3>
                <div className="bg-slate-900 border border-slate-600 rounded p-3 font-mono text-sm overflow-x-auto">
                  <span className="text-emerald-400">$</span> <span className="text-slate-300">nmap -p443 --script tls-expired-cert-checker target.com</span>
                </div>
              </CardContent>
            </Card>
          </aside>

          {/* Main Content Area */}
          <main className="flex-1 min-w-0">
            {/* Desktop Navigation Tabs */}
            <div className="hidden md:block">
              <Tabs value={activeSection} onValueChange={setActiveSection} className="space-y-6">
                <TabsList className="grid w-full grid-cols-5 bg-slate-800/50">
                  <TabsTrigger value="scanner" className="flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    <span className="hidden lg:inline">Scanner</span>
                  </TabsTrigger>
                  <TabsTrigger value="batch" className="flex items-center gap-2">
                    <Upload className="w-4 h-4" />
                    <span className="hidden lg:inline">Batch</span>
                  </TabsTrigger>
                  <TabsTrigger value="scheduled" className="flex items-center gap-2">
                    <Calendar className="w-4 h-4" />
                    <span className="hidden lg:inline">Schedule</span>
                  </TabsTrigger>
                  <TabsTrigger value="export" className="flex items-center gap-2">
                    <Database className="w-4 h-4" />
                    <span className="hidden lg:inline">Export</span>
                  </TabsTrigger>
                  <TabsTrigger value="script" className="flex items-center gap-2">
                    <Code className="w-4 h-4" />
                    <span className="hidden lg:inline">Script</span>
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="scanner" className="space-y-6">
                  <CertificateTester />
                </TabsContent>

                <TabsContent value="batch" className="space-y-6">
                  <BatchScanner />
                </TabsContent>

                <TabsContent value="scheduled" className="space-y-6">
                  <ScheduledScans />
                </TabsContent>

                <TabsContent value="export" className="space-y-6">
                  <ExportTools />
                </TabsContent>

                <TabsContent value="script" className="space-y-6">
                  <NSEScript />
                  
                  {/* Certificate Status Examples */}
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-semibold mb-4 flex items-center">
                        <List className="text-purple-400 mr-2" />
                        Example Output Status
                      </h3>
                      
                      <div className="space-y-3">
                        <div className="flex items-center space-x-3 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded">
                          <span className="text-emerald-400 text-lg">✅</span>
                          <span className="text-emerald-300">Certificado válido por 245 dias.</span>
                        </div>
                        
                        <div className="flex items-center space-x-3 p-3 bg-amber-500/10 border border-amber-500/30 rounded">
                          <span className="text-amber-400 text-lg">⚠️</span>
                          <span className="text-amber-300">Certificado válido por apenas 14 dias.</span>
                        </div>
                        
                        <div className="flex items-center space-x-3 p-3 bg-red-500/10 border border-red-500/30 rounded">
                          <span className="text-red-400 text-lg">❌</span>
                          <span className="text-red-300">Certificado expirado há 5 dias!</span>
                        </div>
                        
                        <div className="flex items-center space-x-3 p-3 bg-slate-600/20 border border-slate-600 rounded">
                          <span className="text-slate-400 text-lg">❓</span>
                          <span className="text-slate-400">Certificado não encontrado ou inválido.</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </div>

            {/* Mobile Content */}
            <div className="md:hidden space-y-6">
              {activeSection === "scanner" && <CertificateTester />}
              {activeSection === "batch" && <BatchScanner />}
              {activeSection === "scheduled" && <ScheduledScans />}
              {activeSection === "export" && <ExportTools />}
              {activeSection === "script" && (
                <div className="space-y-6">
                  <NSEScript />
                  
                  {/* Certificate Status Examples */}
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-semibold mb-4 flex items-center">
                        <List className="text-purple-400 mr-2" />
                        Example Output Status
                      </h3>
                      
                      <div className="space-y-3">
                        <div className="flex items-center space-x-3 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded">
                          <span className="text-emerald-400 text-lg">✅</span>
                          <span className="text-emerald-300">Certificado válido por 245 dias.</span>
                        </div>
                        
                        <div className="flex items-center space-x-3 p-3 bg-amber-500/10 border border-amber-500/30 rounded">
                          <span className="text-amber-400 text-lg">⚠️</span>
                          <span className="text-amber-300">Certificado válido por apenas 14 dias.</span>
                        </div>
                        
                        <div className="flex items-center space-x-3 p-3 bg-red-500/10 border border-red-500/30 rounded">
                          <span className="text-red-400 text-lg">❌</span>
                          <span className="text-red-300">Certificado expirado há 5 dias!</span>
                        </div>
                        
                        <div className="flex items-center space-x-3 p-3 bg-slate-600/20 border border-slate-600 rounded">
                          <span className="text-slate-400 text-lg">❓</span>
                          <span className="text-slate-400">Certificado não encontrado ou inválido.</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </div>
          </main>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-slate-800/30 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-center justify-between">
            <div className="text-sm text-slate-400">
              <p>NSE Script for TLS Certificate Expiration Detection</p>
              <p className="mt-1">Part of the Nmap Security Scanner project</p>
            </div>
            <div className="flex items-center space-x-4 text-slate-400">
              <Button variant="ghost" size="sm" className="hover:text-slate-200">
                <Github />
              </Button>
              <Button variant="ghost" size="sm" className="hover:text-slate-200">
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
              </Button>
              <Button variant="ghost" size="sm" className="hover:text-slate-200">
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                </svg>
              </Button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
