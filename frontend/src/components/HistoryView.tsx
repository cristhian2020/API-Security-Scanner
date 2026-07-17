// src/components/HistoryView.tsx
import { useState, useEffect } from "react";
import { onAuthChange } from "../lib/auth";
import type { User } from "firebase/auth";
import ScanResults, { type ScanResult } from "./ScanResults";

const API_BASE = "http://localhost:8000";

export default function HistoryView() {
  const [user, setUser] = useState<User | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [searchTerm, setSearchTerm] = useState("");
  const [scoreFilter, setScoreFilter] = useState("ALL");

  // Modal State
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  useEffect(() => {
    const unsub = onAuthChange((u) => {
      setUser(u);
      if (!u) window.location.href = "/login";
    });
    return () => unsub();
  }, []);

  useEffect(() => {
    if (user) {
      loadHistory();
    }
  }, [user]);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const token = await user!.getIdToken();
      const res = await fetch(`${API_BASE}/api/history`, {
        headers: { "Authorization": `Bearer ${token}` }
      });
      const data = await res.json();
      setHistory(data);
    } catch {
      console.error("Error cargando historial");
    }
    setLoading(false);
  };

  // Filtrado de historial
  const filteredHistory = history.filter((scan) => {
    const matchesSearch = (scan.url || "").toLowerCase().includes(searchTerm.toLowerCase());
    const matchesScore = scoreFilter === "ALL" || (scan.score && scan.score.startsWith(scoreFilter));
    return matchesSearch && matchesScore;
  });

  if (!user) return null;

  return (
    <div className="max-w-6xl mx-auto">
      {/* Modal de Detalles */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm overflow-y-auto">
          <div className="min-h-screen py-8 px-4">
            <div className="max-w-5xl mx-auto">
              <div className="flex justify-end mb-4">
                <button 
                  onClick={() => setSelectedScan(null)}
                  className="text-white hover:text-red-400 font-bold text-lg bg-slate-800 hover:bg-slate-700 rounded-full w-10 h-10 flex items-center justify-center transition-colors"
                >
                  ✕
                </button>
              </div>
              <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-4 sm:p-6">
                <ScanResults results={selectedScan} />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="glass-card p-8">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
          <h2 className="text-2xl font-bold text-white">📋 Historial de Escaneos</h2>
          <button onClick={loadHistory} className="btn-primary !px-4 !py-2 text-sm">
            <span>🔄</span> Actualizar
          </button>
        </div>

        {/* Filtros */}
        <div className="flex flex-col md:flex-row gap-4 mb-6 bg-slate-800/50 p-4 rounded-xl border border-slate-700/50">
          <div className="flex-1">
            <label className="block text-xs text-slate-400 font-semibold mb-1">Buscar por URL</label>
            <input 
              type="text" 
              placeholder="Ej. api.github.com..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input-dark w-full !py-2 text-sm"
            />
          </div>
          <div className="w-full md:w-48">
            <label className="block text-xs text-slate-400 font-semibold mb-1">Filtrar por Score</label>
            <select 
              value={scoreFilter} 
              onChange={(e) => setScoreFilter(e.target.value)}
              className="input-dark w-full !py-2 text-sm"
            >
              <option value="ALL">Todos</option>
              <option value="A">Score A</option>
              <option value="B">Score B</option>
              <option value="C">Score C</option>
              <option value="D">Score D</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto w-full">
          <table className="w-full text-left border-collapse whitespace-nowrap">
            <thead>
              <tr className="border-b border-slate-700/50 text-slate-400 text-sm">
                <th className="p-4 font-semibold">Fecha</th>
                <th className="p-4 font-semibold w-1/3">URL Escaneada</th>
                <th className="p-4 font-semibold text-center">Score</th>
                <th className="p-4 font-semibold text-center">Críticas</th>
                <th className="p-4 font-semibold text-center">Acciones</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    <div className="animate-spin h-8 w-8 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
                    Cargando...
                  </td>
                </tr>
              ) : filteredHistory.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    No se encontraron escaneos que coincidan con los filtros.
                  </td>
                </tr>
              ) : (
                filteredHistory.map((scan: any, i) => (
                  <tr key={i} className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 text-slate-300">
                      {new Date(scan.date || scan.started_at).toLocaleString('es-ES', {
                        day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute:'2-digit'
                      })}
                    </td>
                    <td className="p-4 font-medium text-white max-w-[150px] sm:max-w-xs md:max-w-md truncate" title={scan.url}>
                      {scan.url}
                    </td>
                    <td className="p-4 text-center">
                      <span className={`font-bold text-lg score-${(scan.score || "N/A").replace("+", "plus")}`}>
                        {scan.score || "N/A"}
                      </span>
                    </td>
                    <td className="p-4 text-center font-bold text-red-400">{scan.critical_count || 0}</td>
                    <td className="p-4 text-center space-x-2">
                      <button 
                        onClick={() => setSelectedScan(scan)}
                        className="text-white hover:text-white bg-blue-600 hover:bg-blue-500 px-3 py-1.5 rounded-md transition-colors text-xs font-bold shadow-lg"
                      >
                        👁️ Ver Detalles
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
