// src/components/HistoryView.tsx
import { useState, useEffect } from "react";
import { onAuthChange } from "../lib/auth";
import type { User } from "firebase/auth";

const API_BASE = "http://localhost:8000";

export default function HistoryView() {
  const [user, setUser] = useState<User | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

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

  if (!user) return null;

  return (
    <div className="max-w-6xl mx-auto">
      <div className="glass-card p-8">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-white">📋 Historial de Escaneos</h2>
          <button onClick={loadHistory} className="btn-primary !px-4 !py-2 text-sm">
            <span>🔄</span> Actualizar
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-700/50 text-slate-400 text-sm">
                <th className="p-4 font-semibold">Fecha</th>
                <th className="p-4 font-semibold">URL Escaneada</th>
                <th className="p-4 font-semibold text-center">Score</th>
                <th className="p-4 font-semibold text-center">Críticas</th>
                <th className="p-4 font-semibold text-center">Altas</th>
                <th className="p-4 font-semibold text-center">Acciones</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {loading ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500">
                    <div className="animate-spin h-8 w-8 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
                    Cargando...
                  </td>
                </tr>
              ) : history.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500">
                    No hay escaneos anteriores. ¡Inicia uno ahora!
                  </td>
                </tr>
              ) : (
                history.map((scan, i) => (
                  <tr key={i} className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 text-slate-300">{new Date(scan.date || scan.started_at).toLocaleString('es-ES')}</td>
                    <td className="p-4 font-medium text-white">{scan.url}</td>
                    <td className="p-4 text-center">
                      <span className={`font-bold text-lg score-${(scan.score || "N/A").replace("+", "plus")}`}>
                        {scan.score || "N/A"}
                      </span>
                    </td>
                    <td className="p-4 text-center font-bold text-red-400">{scan.critical_count || 0}</td>
                    <td className="p-4 text-center font-bold text-orange-400">{scan.high_count || 0}</td>
                    <td className="p-4 text-center">
                      <a href={`${API_BASE}/api/report/${scan.id}`} download
                        className="text-purple-400 hover:text-purple-300 bg-purple-500/10 hover:bg-purple-500/20 px-3 py-1.5 rounded-md transition-colors text-xs font-medium border border-purple-500/20">
                        JSON
                      </a>
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
