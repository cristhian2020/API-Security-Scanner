// src/components/Scanner.tsx
import { useState, useEffect } from "react";
import { onAuthChange } from "../lib/auth";
import type { User } from "firebase/auth";

const API_BASE = "http://localhost:8000";

import ScanResults, { type ScanResult } from "./ScanResults";

export default function Scanner() {
  const [user, setUser] = useState<User | null>(null);
  const [scanMode, setScanMode] = useState<"url" | "openapi">("url");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [authToken, setAuthToken] = useState("");
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
        if (authToken.trim()) {
          formData.append("auth_token", authToken.trim());
        }
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
            {/* <label className="flex items-center gap-2 cursor-pointer">
              <input type="radio" name="mode" checked={scanMode === "openapi"}
                onChange={() => setScanMode("openapi")}
                className="accent-purple-500" />
              <span className="text-sm text-slate-300">Subir OpenAPI (Swagger)</span>
            </label> */}
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
                <div className="mt-2">
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Token JWT (Opcional)</label>
                  <input 
                    type="text" 
                    value={authToken} 
                    onChange={(e) => setAuthToken(e.target.value)} 
                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." 
                    className="input-dark text-xs py-2"
                  />
                  <p className="text-[15px] text-slate-500 mt-1">Si la API requiere autenticación, ingresa el token aquí para escanear vulnerabilidades en JWT.</p>
                </div>
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
        <ScanResults results={results} />
      )}
    </div>
  );
}
