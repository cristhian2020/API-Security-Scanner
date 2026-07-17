// src/components/DashboardView.tsx
import { useState, useEffect, useRef } from "react";
import { onAuthChange } from "../lib/auth";
import type { User } from "firebase/auth";

const API_BASE = "http://localhost:8000";

// Importar Chart.js dinámicamente
let Chart: any;

export default function DashboardView() {
  const [user, setUser] = useState<User | null>(null);
  const [data, setData] = useState<any>(null);
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(true);
  const trendChartRef = useRef<HTMLCanvasElement>(null);
  const distChartRef = useRef<HTMLCanvasElement>(null);
  const trendInstance = useRef<any>(null);
  const distInstance = useRef<any>(null);

  const [chartLoaded, setChartLoaded] = useState(false);

  useEffect(() => {
    const unsub = onAuthChange((u) => {
      setUser(u);
      if (!u) window.location.href = "/login";
    });
    return () => unsub();
  }, []);

  // 1. Cargar Chart.js una sola vez al montar
  useEffect(() => {
    if (typeof window !== "undefined" && !Chart) {
      import("https://cdn.jsdelivr.net/npm/chart.js@4.4.7/+esm" as any).then((mod) => {
        Chart = mod.Chart;
        const { CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Filler, Legend, Tooltip, LineController, DoughnutController } = mod;
        Chart.register(CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Filler, Legend, Tooltip, LineController, DoughnutController);
        setChartLoaded(true);
      }).catch(() => {
        console.error("No se pudo cargar Chart.js");
      });
    } else if (Chart) {
      setChartLoaded(true);
    }
  }, []);

  // 2. Cargar los datos cuando el usuario o los días cambian
  useEffect(() => {
    if (user) {
      loadDashboard();
    }
  }, [days, user]);

  // 3. Renderizar gráficos una vez que los datos cargaron y el DOM está listo
  useEffect(() => {
    if (!loading && data && chartLoaded) {
      // Pequeño delay para asegurar que los refs (canvas) estén montados en el DOM
      const timer = setTimeout(() => {
        renderCharts(data);
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [loading, data, chartLoaded]);

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const token = user ? await user.getIdToken() : null;
      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/api/dashboard/full?days=${days}`, { headers });
      const json = await res.json();
      setData(json);
    } catch {
      console.error("Error loading dashboard");
    } finally {
      setLoading(false);
    }
  };

  const renderCharts = (d: any) => {
    if (!Chart || !d) return;

    // Trend Chart
    if (trendChartRef.current) {
      if (trendInstance.current) trendInstance.current.destroy();
      trendInstance.current = new Chart(trendChartRef.current, {
        type: "line",
        data: {
          labels: d.trends?.dates || [],
          datasets: [
            { label: "Críticas", data: d.trends?.critical || [], borderColor: "#ef4444", backgroundColor: "rgba(239,68,68,0.1)", fill: true, tension: 0.4 },
            { label: "Altas", data: d.trends?.high || [], borderColor: "#f97316", backgroundColor: "rgba(249,115,22,0.1)", fill: true, tension: 0.4 },
            { label: "Medias", data: d.trends?.medium || [], borderColor: "#eab308", backgroundColor: "rgba(234,179,8,0.1)", fill: true, tension: 0.4 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { color: "#94a3b8" } } },
          scales: {
            y: { beginAtZero: true, grid: { color: "rgba(100,116,139,0.1)" }, ticks: { color: "#94a3b8" } },
            x: { grid: { display: false }, ticks: { color: "#94a3b8" } },
          },
        },
      });
    }

    // Distribution Chart
    if (distChartRef.current) {
      if (distInstance.current) distInstance.current.destroy();
      const dist = d.distribution || {};
      distInstance.current = new Chart(distChartRef.current, {
        type: "doughnut",
        data: {
          labels: ["Críticas", "Altas", "Medias", "Bajas"],
          datasets: [{ data: [dist.critical || 0, dist.high || 0, dist.medium || 0, dist.low || 0], backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"], borderWidth: 0 }],
        },
        options: {
          responsive: true, maintainAspectRatio: false, cutout: "70%",
          plugins: { legend: { position: "bottom", labels: { color: "#94a3b8" } } },
        },
      });
    }
  };

  if (!user || loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-slate-400">Cargando dashboard...</p>
        </div>
      </div>
    );
  }

  const summary = data?.summary || {};
  const freqVulns = data?.frequent_vulnerabilities || [];
  const urls = data?.url_analysis || [];

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold text-white">📊 Panel de Inteligencia</h2>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}
          className="input-dark !w-auto !py-2 text-sm">
          <option value={7}>Últimos 7 días</option>
          <option value={30}>Últimos 30 días</option>
          <option value={90}>Últimos 90 días</option>
        </select>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-6 border-l-4 border-purple-500">
          <div className="text-xs text-slate-400 font-medium mb-1">Total Escaneos</div>
          <div className="text-3xl font-bold text-white">{summary.total_scans || 0}</div>
        </div>
        <div className="glass-card p-6 border-l-4 border-red-500">
          <div className="text-xs text-slate-400 font-medium mb-1">Vulnerabilidades Críticas</div>
          <div className="text-3xl font-bold text-white">{summary.total_critical || 0}</div>
        </div>
        <div className="glass-card p-6 border-l-4 border-green-500">
          <div className="text-xs text-slate-400 font-medium mb-1">Score Promedio</div>
          <div className={`text-3xl font-bold score-${(summary.avg_score || "N/A").replace("+", "plus")}`}>
            {summary.avg_score || "N/A"}
          </div>
        </div>
        <div className="glass-card p-6 border-l-4 border-blue-500">
          <div className="text-xs text-slate-400 font-medium mb-1">APIs Analizadas</div>
          <div className="text-3xl font-bold text-white">{summary.unique_urls || 0}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-card p-6 lg:col-span-2">
          <h3 className="text-lg font-bold text-white mb-4">Evolución de Vulnerabilidades</h3>
          <div className="h-72"><canvas ref={trendChartRef} /></div>
        </div>
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Distribución por Severidad</h3>
          <div className="h-72"><canvas ref={distChartRef} /></div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Frequent Vulns */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Vulnerabilidades más Frecuentes</h3>
          <div className="space-y-3 max-h-80 overflow-y-auto pr-2">
            {freqVulns.length > 0 ? freqVulns.map((v: any, i: number) => (
              <div key={i} className="flex justify-between items-center pb-3 border-b border-slate-700/50 last:border-0">
                <div>
                  <h4 className="text-sm font-semibold text-white">{v.title}</h4>
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium mt-1 badge-${v.severity}`}>
                    {v.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-right">
                  <div className="text-lg font-bold text-white">{v.count}</div>
                  <div className="text-xs text-slate-500">veces</div>
                </div>
              </div>
            )) : (
              <p className="text-slate-500 text-center py-8">No hay datos suficientes</p>
            )}
          </div>
        </div>

        {/* API Risk */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Estado por API (Top 5)</h3>
          <div className="space-y-4 max-h-80 overflow-y-auto pr-2">
            {urls.length > 0 ? urls.sort((a: any, b: any) => b.total_issues - a.total_issues).slice(0, 5).map((api: any, i: number) => {
              const pct = Math.min((api.total_issues / 20) * 100, 100);
              const color = api.critical_issues > 0 ? "bg-red-500" : api.high_issues > 0 ? "bg-orange-500" : "bg-green-500";
              return (
                <div key={i} className="pb-3 border-b border-slate-700/50 last:border-0">
                  <div className="flex justify-between items-end mb-1">
                    <span className="text-sm font-medium text-white truncate pr-4">{api.url}</span>
                    <span className="text-xs text-slate-400">{api.total_issues} issues</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-1.5 mb-1">
                    <div className={`${color} h-1.5 rounded-full`} style={{ width: `${pct}%` }} />
                  </div>
                  <div className="flex justify-between text-xs text-slate-500">
                    <span><span className="text-red-400 font-bold">{api.critical_issues}</span> Críticas</span>
                    <span><span className="text-orange-400 font-bold">{api.high_issues}</span> Altas</span>
                  </div>
                </div>
              );
            }) : (
              <p className="text-slate-500 text-center py-8">No hay APIs analizadas</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
