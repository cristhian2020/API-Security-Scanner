// src/components/Scanner.tsx
import { useState, useEffect } from "react";
import { onAuthChange } from "../lib/auth";
import type { User } from "firebase/auth";

const API_BASE = "http://localhost:8000";

interface Vulnerability {
  title: string;
  severity: string;
  description: string;
  impact: string;
  recommendation: string;
  code_example?: string;
  link?: string;
}

interface ScanResult {
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

export default function Scanner() {
  const [user, setUser] = useState<User | null>(null);
  const [scanMode, setScanMode] = useState<"url" | "openapi">("url");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [deepScan, setDeepScan] = useState(true);
  const [sslCheck, setSslCheck] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [results, setResults] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);

  useEffect(() => {
    const unsub = onAuthChange((u) => {
      setUser(u);
      if (!u) window.location.href = "/login";
    });
    return () => unsub();
  }, []);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (scanMode === "url" && !url.trim()) return;
    if (scanMode === "openapi" && !file) return;

    setScanning(true);
    setProgress(0);
    setResults(null);
    setStatusMessage("Iniciando escaneo...");

    try {
      const formData = new FormData();
      let endpoint = `${API_BASE}/api/scan`;

      if (scanMode === "url") {
        formData.append("url", url);
        formData.append("deep_scan", String(deepScan));
        formData.append("ssl_check", String(sslCheck));
      } else {
        formData.append("file", file!);
        endpoint = `${API_BASE}/api/scan/file`;
      }

      // Get the user's Firebase token to send to the backend
      const token = user ? await user.getIdToken() : null;
      
      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const response = await fetch(endpoint, {
        method: "POST",
        body: formData,
        headers,
      });

      const data = await response.json();

      if (data.status === "started") {
        setScanId(data.scan_id);
        monitorProgress(data.scan_id, token);
      }
    } catch (err) {
      setStatusMessage("Error al iniciar el escaneo.");
      setScanning(false);
    }
  };

  const monitorProgress = (id: string, token: string | null) => {
    const interval = setInterval(async () => {
      try {
        const headers: Record<string, string> = {};
        if (token) headers["Authorization"] = `Bearer ${token}`;

        const res = await fetch(`${API_BASE}/api/status/${id}`, { headers });
        const data = await res.json();

        setProgress(data.progress);
        setStatusMessage(data.message);

        if (data.status === "completed") {
          clearInterval(interval);
          loadResults(id, token);
        } else if (data.status === "failed") {
          clearInterval(interval);
          setStatusMessage("Error: " + data.error);
          setScanning(false);
        }
      } catch {
        // retry silently
      }
    }, 1000);
  };

  const loadResults = async (id: string, token: string | null) => {
    try {
      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/api/report/${id}`, { headers });
      const data: ScanResult = await res.json();
      setResults(data);
      setScanning(false);
    } catch {
      setStatusMessage("Error cargando resultados.");
      setScanning(false);
    }
  };

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

  if (!user) return null;

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Scan Form */}
      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold text-white mb-2">🔍 Escanea tu API</h2>
        <p className="text-slate-400 mb-6">Ingresa la URL de tu API para analizar su seguridad</p>

        <form onSubmit={startScan}>
          {/* Mode Toggle */}
          <div className="flex gap-4 mb-5">
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="radio" name="mode" checked={scanMode === "url"}
                onChange={() => setScanMode("url")}
                className="accent-purple-500" />
              <span className="text-sm text-slate-300">Escanear URL</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="radio" name="mode" checked={scanMode === "openapi"}
                onChange={() => setScanMode("openapi")}
                className="accent-purple-500" />
              <span className="text-sm text-slate-300">Subir OpenAPI (Swagger)</span>
            </label>
          </div>

          {/* URL Input */}
          {scanMode === "url" && (
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="input-dark mb-4"
              placeholder="https://api.tudominio.com/v1"
              required
            />
          )}

          {/* File Input */}
          {scanMode === "openapi" && (
            <input
              type="file"
              accept=".json,.yaml,.yml"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="input-dark mb-4 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-purple-600 file:text-white hover:file:bg-purple-700"
              required
            />
          )}

          {/* Advanced Options */}
          {scanMode === "url" && (
            <details className="mb-5">
              <summary className="text-sm text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">
                ⚙️ Opciones avanzadas
              </summary>
              <div className="mt-3 p-4 rounded-xl bg-slate-800/50 border border-slate-700/50 space-y-3">
                <label className="flex items-center gap-3 text-sm">
                  <input type="checkbox" checked={deepScan} onChange={(e) => setDeepScan(e.target.checked)}
                    className="accent-purple-500 rounded" />
                  <span className="text-slate-300">Escaneo profundo (SQLi + Rate Limiting)</span>
                </label>
                <label className="flex items-center gap-3 text-sm">
                  <input type="checkbox" checked={sslCheck} onChange={(e) => setSslCheck(e.target.checked)}
                    className="accent-purple-500 rounded" />
                  <span className="text-slate-300">Verificar certificado SSL/TLS</span>
                </label>
              </div>
            </details>
          )}

          <button type="submit" disabled={scanning} className="btn-primary w-full md:w-auto flex items-center justify-center gap-2">
            {scanning ? "⏳ Escaneando..." : "🚀 Iniciar Escaneo"}
          </button>
        </form>
      </div>

      {/* Progress */}
      {scanning && (
        <div className="glass-card p-6 fade-in">
          <div className="flex justify-between items-center mb-3">
            <span className="text-sm font-medium text-slate-300">{statusMessage}</span>
            <span className="text-sm font-bold text-purple-400">{progress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2.5">
            <div className="gradient-bg h-2.5 rounded-full transition-all duration-500"
              style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-6 fade-in">
          {/* Score */}
          <div className="glass-card p-8 flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold text-white">Puntuación de Seguridad</h3>
              <p className="text-slate-400 text-sm">Basado en estándares CVSS y OWASP API Security Top 10</p>
            </div>
            <div className={`text-6xl font-extrabold score-${results.score.replace("+", "plus")}`}>
              {results.score}
            </div>
          </div>

          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="glass-card p-5 border-l-4 border-red-500">
              <div className="text-red-400 text-xs font-semibold mb-1">Críticas</div>
              <div className="text-3xl font-bold text-white">{results.critical_count}</div>
            </div>
            <div className="glass-card p-5 border-l-4 border-orange-500">
              <div className="text-orange-400 text-xs font-semibold mb-1">Altas</div>
              <div className="text-3xl font-bold text-white">{results.summary.high?.length || 0}</div>
            </div>
            <div className="glass-card p-5 border-l-4 border-yellow-500">
              <div className="text-yellow-400 text-xs font-semibold mb-1">Medias</div>
              <div className="text-3xl font-bold text-white">{results.medium_count}</div>
            </div>
            <div className="glass-card p-5 border-l-4 border-green-500">
              <div className="text-green-400 text-xs font-semibold mb-1">Seguras</div>
              <div className="text-3xl font-bold text-white">{results.secure_count}</div>
            </div>
          </div>

          {/* Vulnerability List */}
          <div className="glass-card p-8">
            <h3 className="text-xl font-bold text-white mb-6">Hallazgos Detallados</h3>

            {results.vulnerabilities.length === 0 ? (
              <div className="bg-green-500/10 border border-green-500/30 p-6 rounded-xl">
                <h4 className="text-green-400 font-bold text-lg mb-1">✅ ¡No se encontraron vulnerabilidades!</h4>
                <p className="text-green-300/70 text-sm">Tu API tiene una configuración de seguridad excelente.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {results.vulnerabilities.map((vuln, i) => {
                  const badge = getSeverityBadge(vuln.severity);
                  return (
                    <div key={i} className={`p-6 rounded-xl bg-slate-800/50 severity-${vuln.severity}`}>
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="font-bold text-white">{vuln.title}</h4>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${badge.cls}`}>{badge.label}</span>
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
                          <div className="code-block text-xs">{vuln.code_example}</div>
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
      )}
    </div>
  );
}
