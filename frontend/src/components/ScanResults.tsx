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
    if (isGenerating) return;
    setIsGenerating(true);

    try {
      const printWindow = window.open('', '_blank');
      if (!printWindow) {
        alert("Por favor permite las ventanas emergentes para descargar el PDF.");
        setIsGenerating(false);
        return;
      }

      const now = new Date();
      const dateStr = now.toLocaleDateString('es-ES', { day: '2-digit', month: 'long', year: 'numeric' });
      const timeStr = now.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
      const scoreColors: Record<string, string> = { 'A+': '#22c55e', 'A': '#4ade80', 'B': '#facc15', 'C': '#fb923c', 'D': '#ef4444' };
      const scoreColor = scoreColors[results.score] || '#94a3b8';
      const sevColors: Record<string, {bg: string, text: string, label: string}> = {
        critical: { bg: '#fef2f2', text: '#dc2626', label: 'CRÍTICO' },
        high:     { bg: '#fff7ed', text: '#ea580c', label: 'ALTO' },
        medium:   { bg: '#fefce8', text: '#ca8a04', label: 'MEDIO' },
        low:      { bg: '#f0fdf4', text: '#16a34a', label: 'BAJO' },
        info:     { bg: '#eff6ff', text: '#2563eb', label: 'INFO' },
      };

      const vulns = results.vulnerabilities || [];
      const critCount = results.critical_count || 0;
      const highCount = results.summary?.high?.length || results.high_count || 0;
      const medCount = results.medium_count || 0;
      const secCount = results.secure_count || 0;
      const totalVulns = vulns.filter(v => v.severity !== 'info').length;

      // Generar filas de vulnerabilidades
      const vulnRows = vulns.map((v, i) => {
        const sev = sevColors[v.severity] || sevColors.info;
        return `
          <div class="finding" style="page-break-inside: avoid;">
            <div class="finding-header">
              <div class="finding-number">#${i + 1}</div>
              <div class="finding-title">${v.title}</div>
              <div class="severity-badge" style="background:${sev.bg}; color:${sev.text};">${sev.label}</div>
            </div>
            <p class="finding-desc">${v.description}</p>
            <div class="finding-details">
              <div class="detail-box impact">
                <div class="detail-label">💥 Impacto</div>
                <p>${v.impact}</p>
              </div>
              <div class="detail-box recommendation">
                <div class="detail-label">📝 Recomendación</div>
                <p>${v.recommendation}</p>
              </div>
            </div>
            ${v.code_example ? `
              <div class="code-section">
                <div class="detail-label">Ejemplo de solución</div>
                <pre>${v.code_example}</pre>
              </div>
            ` : ''}
            ${v.link ? `<div class="ref-link"><a href="${v.link}" target="_blank">🔗 Referencia OWASP</a></div>` : ''}
          </div>
        `;
      }).join('');

      printWindow.document.write(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Reporte de Seguridad API - ${results.url || 'API'}</title>
  <style>
    @page { size: letter; margin: 1.5cm 2cm; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; color: #1e293b; line-height: 1.6; background: #fff; }
    
    /* HEADER */
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #7c3aed; padding-bottom: 20px; margin-bottom: 30px; }
    .header-left h1 { font-size: 22px; color: #7c3aed; margin-bottom: 4px; }
    .header-left p { font-size: 11px; color: #64748b; }
    .header-right { text-align: right; font-size: 11px; color: #64748b; line-height: 1.8; }
    
    /* SCORE */
    .score-section { text-align: center; margin: 30px 0; padding: 25px; background: linear-gradient(135deg, #f8fafc, #f1f5f9); border-radius: 12px; border: 1px solid #e2e8f0; }
    .score-label { font-size: 13px; color: #64748b; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 8px; }
    .score-value { font-size: 72px; font-weight: 800; color: ${scoreColor}; line-height: 1; }
    .score-url { font-size: 12px; color: #94a3b8; margin-top: 8px; word-break: break-all; }
    
    /* SUMMARY TABLE */
    .summary-section { margin: 30px 0; }
    .summary-section h2 { font-size: 16px; color: #1e293b; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .summary-card { padding: 16px; border-radius: 8px; text-align: center; }
    .summary-card.critical { background: #fef2f2; border-left: 4px solid #ef4444; }
    .summary-card.high { background: #fff7ed; border-left: 4px solid #f97316; }
    .summary-card.medium { background: #fefce8; border-left: 4px solid #eab308; }
    .summary-card.secure { background: #f0fdf4; border-left: 4px solid #22c55e; }
    .summary-card .count { font-size: 28px; font-weight: 800; }
    .summary-card.critical .count { color: #dc2626; }
    .summary-card.high .count { color: #ea580c; }
    .summary-card.medium .count { color: #ca8a04; }
    .summary-card.secure .count { color: #16a34a; }
    .summary-card .label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

    /* FINDINGS */
    .findings-section { margin-top: 30px; }
    .findings-section h2 { font-size: 16px; color: #1e293b; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }
    .finding { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
    .finding-number { background: #7c3aed; color: white; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; flex-shrink: 0; }
    .finding-title { font-size: 14px; font-weight: 700; color: #0f172a; flex: 1; }
    .severity-badge { padding: 3px 12px; border-radius: 20px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px; flex-shrink: 0; }
    .finding-desc { font-size: 12px; color: #475569; margin-bottom: 12px; }
    .finding-details { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .detail-box { padding: 12px; border-radius: 6px; font-size: 11px; color: #334155; }
    .detail-box.impact { background: #fef2f2; border: 1px solid #fecaca; }
    .detail-box.recommendation { background: #f0fdf4; border: 1px solid #bbf7d0; }
    .detail-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; color: #64748b; }
    .code-section { margin-top: 10px; }
    .code-section pre { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; font-size: 10px; font-family: 'Consolas', 'Monaco', monospace; white-space: pre-wrap; word-break: break-word; overflow: hidden; }
    .ref-link { margin-top: 8px; text-align: right; }
    .ref-link a { color: #7c3aed; font-size: 11px; text-decoration: none; }
    
    /* FOOTER */
    .footer { margin-top: 40px; padding-top: 16px; border-top: 2px solid #e2e8f0; display: flex; justify-content: space-between; font-size: 10px; color: #94a3b8; }
    
    /* NO VULNS */
    .no-vulns { text-align: center; padding: 30px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; }
    .no-vulns h3 { color: #16a34a; font-size: 16px; }
    .no-vulns p { color: #64748b; font-size: 12px; margin-top: 4px; }

    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .finding { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>🛡️ API Security Scanner</h1>
      <p>Reporte de Análisis de Vulnerabilidades</p>
    </div>
    <div class="header-right">
      <div><strong>Fecha:</strong> ${dateStr}</div>
      <div><strong>Hora:</strong> ${timeStr}</div>
      <div><strong>Vulnerabilidades:</strong> ${totalVulns} encontradas</div>
    </div>
  </div>

  <!-- SCORE -->
  <div class="score-section">
    <div class="score-label">Puntuación de Seguridad</div>
    <div class="score-value">${results.score || 'N/A'}</div>
    <div class="score-url">${results.url || 'URL no especificada'}</div>
  </div>

  <!-- RESUMEN -->
  <div class="summary-section">
    <h2>Resumen Ejecutivo</h2>
    <div class="summary-grid">
      <div class="summary-card critical"><div class="count">${critCount}</div><div class="label">Críticas</div></div>
      <div class="summary-card high"><div class="count">${highCount}</div><div class="label">Altas</div></div>
      <div class="summary-card medium"><div class="count">${medCount}</div><div class="label">Medias</div></div>
      <div class="summary-card secure"><div class="count">${secCount}</div><div class="label">Seguras</div></div>
    </div>
  </div>

  <!-- HALLAZGOS -->
  <div class="findings-section">
    <h2>Hallazgos Detallados</h2>
    ${vulns.length === 0 ? `
      <div class="no-vulns">
        <h3>✅ No se encontraron vulnerabilidades</h3>
        <p>La API analizada presenta una configuración de seguridad sólida.</p>
      </div>
    ` : vulnRows}
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <span>Generado por API Security Scanner — Basado en OWASP API Security Top 10</span>
    <span>Reporte confidencial — ${dateStr}</span>
  </div>
</body>
</html>`);
      printWindow.document.close();
      
      printWindow.onload = () => {
        printWindow.print();
        printWindow.onafterprint = () => printWindow.close();
      };
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
