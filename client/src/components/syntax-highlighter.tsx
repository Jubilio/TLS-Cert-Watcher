interface SyntaxHighlighterProps {
  code: string;
  language: string;
}

export default function SyntaxHighlighter({ code, language }: SyntaxHighlighterProps) {
  const highlightLua = (code: string) => {
    // Lua keywords
    const keywords = ['local', 'function', 'end', 'if', 'then', 'else', 'elseif', 'return', 'require', 'not', 'or', 'and'];
    const builtins = ['math', 'string', 'table', 'os', 'io'];
    
    let highlighted = code;
    
    // Comments
    highlighted = highlighted.replace(/(--.*$)/gm, '<span class="text-slate-500">$1</span>');
    
    // Strings
    highlighted = highlighted.replace(/("[^"]*")/g, '<span class="text-amber-300">$1</span>');
    highlighted = highlighted.replace(/(\[\[[\s\S]*?\]\])/g, '<span class="text-amber-300">$1</span>');
    
    // Numbers
    highlighted = highlighted.replace(/\b(\d+)\b/g, '<span class="text-red-300">$1</span>');
    
    // Keywords
    keywords.forEach(keyword => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'g');
      highlighted = highlighted.replace(regex, `<span class="text-purple-400">${keyword}</span>`);
    });
    
    // Built-in functions and libraries
    builtins.forEach(builtin => {
      const regex = new RegExp(`\\b${builtin}\\b`, 'g');
      highlighted = highlighted.replace(regex, `<span class="text-blue-300">${builtin}</span>`);
    });
    
    // Function names and method calls
    highlighted = highlighted.replace(/(\w+)(\s*\()/g, '<span class="text-emerald-300">$1</span>$2');
    highlighted = highlighted.replace(/(\w+)\.(\w+)/g, '<span class="text-blue-300">$1</span>.<span class="text-emerald-300">$2</span>');
    
    // Variables and identifiers
    highlighted = highlighted.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g, (match) => {
      // Don't highlight if already highlighted
      if (match.includes('<span')) return match;
      return `<span class="text-blue-300">${match}</span>`;
    });
    
    return highlighted;
  };

  const getHighlightedCode = () => {
    if (language === 'lua') {
      return highlightLua(code);
    }
    return code;
  };

  return (
    <pre className="font-mono text-sm text-slate-300 whitespace-pre-wrap">
      <code 
        dangerouslySetInnerHTML={{ 
          __html: getHighlightedCode() 
        }} 
      />
    </pre>
  );
}
