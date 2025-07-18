import { Button } from "@/components/ui/button";
import { Menu, Search, Upload, Calendar, Download, Code } from "lucide-react";

interface MobileNavProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

export default function MobileNav({ activeSection, onSectionChange }: MobileNavProps) {
  const navItems = [
    { id: 'scanner', label: 'Scanner', icon: Search },
    { id: 'batch', label: 'Batch', icon: Upload },
    { id: 'scheduled', label: 'Schedule', icon: Calendar },
    { id: 'export', label: 'Export', icon: Download },
    { id: 'script', label: 'Script', icon: Code },
  ];

  return (
    <div className="md:hidden">
      <select
        value={activeSection}
        onChange={(e) => onSectionChange(e.target.value)}
        className="bg-slate-700 text-slate-200 border border-slate-600 rounded px-3 py-1 text-sm"
      >
        {navItems.map((item) => (
          <option key={item.id} value={item.id}>
            {item.label}
          </option>
        ))}
      </select>
    </div>
  );
}