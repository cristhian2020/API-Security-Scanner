// src/components/ScanResults.tsx
import { useRef, useState } from "react";

export interface Vulnerability {
  title: string;
  severity: string;
  description: string;
  impact: string;
  recommendation: string;
  code_example?: string;
  link?: string;
}

export interface ScanResult {
  url?: string;
  score: string;
  vulnerabilities: Vulnerability[];
  critical_count: number;
  high_count?: number;
  medium_count: number;
  secure_count: number;
  summary: {
    critical: string[];
    high: string[];
    medium: string[];
    low: string[];
  };
}

interface ScanResultsProps {
  results: ScanResult;
}

export default function ScanResults({ results }: ScanResultsProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  const getSeverityBadge = (severity: string) => {
    const map: Record<string, { cls: string; label: string }> = {
      critical: { cls: "badge-critical", label: "CRÍTICO" },
      high: { cls: "badge-high", label: "ALTO" },
      medium: { cls: "badge-medium", label: "MEDIO" },
      low: { cls: "badge-low", label: "BAJO" },
      info: { cls: "badge-info", label: "INFO" },
    };
    return map[severity] || map.info;
  };

  const handleDownloadPDF = async () => {
    if (!containerRef.current || isGenerating) return;
    setIsGenerating(true);

    try {
      // Crear una ventana nueva con el contenido para imprimir como PDF
      const printWindow = window.open('', '_blank');
      if (!printWindow) {
        alert("Por favor permite las ventanas emergentes para descargar el PDF.");
        setIsGenerating(false);
        return;
      }

      const content = containerRef.current.innerHTML;

      printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Reporte de Seguridad - ${results.url || 'API'}</title>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }
            .space-y-6 > * + * { margin-top: 1.5rem; }
            .space-y-4 > * + * { margin-top: 1rem; }
            .glass-card { background: rgba(30,41,59,0.7); border: 1px solid rgba(71,85,105,0.4); border-radius: 12px; }
            .p-8 { padding: 2rem; }
            .p-5 { padding: 1.25rem; }
            .p-6 { padding: 1.5rem; }
            .p-3 { padding: 0.75rem; }
            .mb-1 { margin-bottom: 0.25rem; }
            .mb-3 { margin-bottom: 0.75rem; }
            .mb-4 { margin-bottom: 1rem; }
            .mb-6 { margin-bottom: 1.5rem; }
            .mt-3 { margin-top: 0.75rem; }
            .text-white { color: white; }
            .text-2xl { font-size: 1.5rem; }
            .text-xl { font-size: 1.25rem; }
            .text-3xl { font-size: 1.875rem; }
            .text-6xl { font-size: 3.75rem; }
            .text-xs { font-size: 0.75rem; }
            .text-sm { font-size: 0.875rem; }
            .font-bold { font-weight: 700; }
            .font-extrabold { font-weight: 800; }
            .font-semibold { font-weight: 600; }
            .text-center { text-align: center; }
            .text-right { text-align: right; }
            .rounded-xl { border-radius: 0.75rem; }
            .rounded-lg { border-radius: 0.5rem; }
            .rounded-full { border-radius: 9999px; }
            .text-slate-300 { color: #cbd5e1; }
            .text-slate-400 { color: #94a3b8; }
            .text-red-400 { color: #f87171; }
            .text-orange-400 { color: #fb923c; }
            .text-yellow-400 { color: #facc15; }
            .text-green-400 { color: #4ade80; }
            .text-purple-400 { color: #c084fc; }
            .border-l-4 { border-left: 4px solid; }
            .border-red-500 { border-color: #ef4444; }
            .border-orange-500 { border-color: #f97316; }
            .border-yellow-500 { border-color: #eab308; }
            .border-green-500 { border-color: #22c55e; }
            .grid { display: grid; gap: 1rem; }
            .grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
            .grid-cols-4 { grid-template-columns: repeat(4, 1fr); }
            .flex { display: flex; }
            .items-center { align-items: center; }
            .justify-between { justify-content: space-between; }
            .gap-3 { gap: 0.75rem; }
            .score-A, .score-Aplus { color: #4ade80; }
            .score-B { color: #facc15; }
            .score-C { color: #fb923c; }
            .score-D { color: #f87171; }
            .badge-critical { background: rgba(239,68,68,0.15); color: #f87171; padding: 4px 12px; border-radius: 9999px; }
            .badge-high { background: rgba(249,115,22,0.15); color: #fb923c; padding: 4px 12px; border-radius: 9999px; }
            .badge-medium { background: rgba(234,179,8,0.15); color: #facc15; padding: 4px 12px; border-radius: 9999px; }
            .badge-low { background: rgba(34,197,94,0.15); color: #4ade80; padding: 4px 12px; border-radius: 9999px; }
            .badge-info { background: rgba(59,130,246,0.15); color: #60a5fa; padding: 4px 12px; border-radius: 9999px; }
            .code-block { background: #1e293b; padding: 12px; border-radius: 8px; font-family: monospace; white-space: pre-wrap; word-break: break-all; }
            .bg-slate-800\\/50 { background: rgba(30,41,59,0.5); }
            @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
          </style>
        </head>
        <body>${content}</body>
        </html>
      `);
      printWindow.document.close();
      
      // Esperar a que cargue y luego imprimir
      printWindow.onload = () => {
        printWindow.print();
        printWindow.onafterprint = () => printWindow.close();
      };
      // Fallback si onload no se dispara
      setTimeout(() => {
        try { printWindow.print(); } catch(e) {}
      }, 1000);

    } catch (error) {
      console.error("Error generando PDF:", error);
      alert("Hubo un error al generar el PDF.");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6 fade-in relative">
      <div className="flex justify-end mb-4">
        <button 
          onClick={handleDownloadPDF} 
          disabled={isGenerating}
          className={`btn-primary flex items-center gap-2 ${isGenerating ? 'opacity-70 cursor-not-allowed' : ''}`}
        >
          {isGenerating ? (
            <>
              <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
              Generando...
            </>
          ) : (
            <>📄 Descargar PDF</>
          )}
        </button>
      </div>

      <div ref={containerRef} className="space-y-6">
        {results.url && (
          <div className="text-center mb-6">
            <h2 className="text-xl text-slate-300">Reporte de Seguridad API</h2>
            <p className="text-purple-400 font-bold break-all">{results.url}</p>
          </div>
        )}

        {/* Score */}
        <div className="glass-card p-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <h3 className="text-2xl font-bold text-white">Puntuación de Seguridad</h3>
            <p className="text-slate-400 text-sm">Basado en estándares CVSS y OWASP API Security Top 10</p>
          </div>
          <div className={`text-6xl font-extrabold score-${(results.score || "N/A").replace("+", "plus")}`}>
            {results.score || "N/A"}
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="glass-card p-5 border-l-4 border-red-500">
            <div className="text-red-400 text-xs font-semibold mb-1">Críticas</div>
            <div className="text-3xl font-bold text-white">{results.critical_count || 0}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-orange-500">
            <div className="text-orange-400 text-xs font-semibold mb-1">Altas</div>
            <div className="text-3xl font-bold text-white">{results.summary?.high?.length || results.high_count || 0}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-yellow-500">
            <div className="text-yellow-400 text-xs font-semibold mb-1">Medias</div>
            <div className="text-3xl font-bold text-white">{results.medium_count || 0}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-green-500">
            <div className="text-green-400 text-xs font-semibold mb-1">Seguras</div>
            <div className="text-3xl font-bold text-white">{results.secure_count || 0}</div>
          </div>
        </div>

        {/* Vulnerability List */}
        <div className="glass-card p-4 sm:p-8">
          <h3 className="text-xl font-bold text-white mb-6">Hallazgos Detallados</h3>

          {(!results.vulnerabilities || results.vulnerabilities.length === 0) ? (
            <div className="bg-green-500/10 border border-green-500/30 p-6 rounded-xl">
              <h4 className="text-green-400 font-bold text-lg mb-1">✅ ¡No se encontraron vulnerabilidades!</h4>
              <p className="text-green-300/70 text-sm">Tu API tiene una configuración de seguridad excelente.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {results.vulnerabilities.map((vuln, i) => {
                const badge = getSeverityBadge(vuln.severity);
                return (
                  <div key={i} className={`p-4 sm:p-6 rounded-xl bg-slate-800/50 severity-${vuln.severity}`}>
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-3 gap-2">
                      <h4 className="font-bold text-white text-sm sm:text-base">{vuln.title}</h4>
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${badge.cls} whitespace-nowrap self-start`}>{badge.label}</span>
                    </div>
                    <p className="text-slate-400 text-sm mb-4">{vuln.description}</p>

                    <div className="grid md:grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                        <h5 className="text-xs font-bold text-red-400 mb-1">💥 Impacto</h5>
                        <p className="text-xs text-slate-400">{vuln.impact}</p>
                      </div>
                      <div className="p-3 rounded-lg bg-green-500/5 border border-green-500/20">
                        <h5 className="text-xs font-bold text-green-400 mb-1">📝 Recomendación</h5>
                        <p className="text-xs text-slate-400">{vuln.recommendation}</p>
                      </div>
                    </div>

                    {vuln.code_example && (
                      <div className="mt-3">
                        <h5 className="text-xs font-semibold text-slate-400 mb-2">Ejemplo de solución:</h5>
                        <div className="code-block text-xs overflow-x-auto">{vuln.code_example}</div>
                      </div>
                    )}

                    {vuln.link && (
                      <div className="mt-3 text-right">
                        <a href={vuln.link} target="_blank" rel="noopener noreferrer"
                          className="text-purple-400 hover:text-purple-300 text-xs font-medium transition-colors">
                          💡 Ver cómo solucionarlo →
                        </a>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
