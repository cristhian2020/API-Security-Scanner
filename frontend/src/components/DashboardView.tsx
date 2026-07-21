// src/components/DashboardView.tsx
import { useState, useEffect } from "react";
import { onAuthChange } from "../lib/auth";
import type { User } from "firebase/auth";
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';

const API_BASE = "http://localhost:8000";

export default function DashboardView() {
  const [user, setUser] = useState<User | null>(null);
  const [data, setData] = useState<any>(null);
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(true);
  const [hiddenLines, setHiddenLines] = useState<Record<string, boolean>>({});
  const [hiddenSlices, setHiddenSlices] = useState<Record<string, boolean>>({});

  const handleLegendClick = (e: any) => {
    const dataKey = e.dataKey;
    if (dataKey) {
      setHiddenLines(prev => ({ ...prev, [dataKey]: !prev[dataKey] }));
    }
  };

  const handlePieLegendClick = (e: any) => {
    const name = e.value;
    if (name) {
      setHiddenSlices(prev => ({ ...prev, [name]: !prev[name] }));
    }
  };

  useEffect(() => {
    const unsub = onAuthChange((u) => {
      setUser(u);
      if (!u) window.location.href = "/login";
    });
    return () => unsub();
  }, []);

  useEffect(() => {
    if (user) {
      loadDashboard();
    }
  }, [days, user]);

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
  
  // Transform data for Recharts
  const trendData = data?.trends?.dates?.map((date: string, i: number) => ({
    name: date,
    critical: data.trends.critical[i] || 0,
    high: data.trends.high[i] || 0,
    medium: data.trends.medium[i] || 0,
    low: data.trends.low?.[i] || 0
  })) || [];

  const dist = data?.distribution || {};
  const distData = [
    { name: "Críticas", value: dist.critical || 0, color: "#ef4444" },
    { name: "Altas", value: dist.high || 0, color: "#f97316" },
    { name: "Medias", value: dist.medium || 0, color: "#eab308" },
    { name: "Bajas", value: dist.low || 0, color: "#3b82f6" },
  ].filter(d => d.value > 0);

  const pieData = distData.map(d => ({
    ...d,
    value: hiddenSlices[d.name] ? 0 : d.value
  }));

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
          <div className="h-72">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.1)" vertical={false} />
                  <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                  <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Legend 
                    wrapperStyle={{ paddingTop: '20px', cursor: 'pointer' }} 
                    onClick={handleLegendClick}
                  />
                  <Line hide={hiddenLines['critical']} type="monotone" dataKey="critical" name="Críticas" stroke={hiddenLines['critical'] ? "#475569" : "#ef4444"} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                  <Line hide={hiddenLines['high']} type="monotone" dataKey="high" name="Altas" stroke={hiddenLines['high'] ? "#475569" : "#f97316"} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                  <Line hide={hiddenLines['medium']} type="monotone" dataKey="medium" name="Medias" stroke={hiddenLines['medium'] ? "#475569" : "#eab308"} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                  <Line hide={hiddenLines['low']} type="monotone" dataKey="low" name="Bajas" stroke={hiddenLines['low'] ? "#475569" : "#3b82f6"} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-400">Sin datos de tendencias</div>
            )}
          </div>
        </div>
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Distribución por Severidad</h3>
          <div className="h-72">
            {distData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    innerRadius={70}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={hiddenSlices[entry.name] ? "#1e293b" : entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Legend 
                    wrapperStyle={{ paddingTop: '20px', cursor: 'pointer' }} 
                    onClick={handlePieLegendClick}
                    formatter={(value) => (
                      <span style={{ color: hiddenSlices[value] ? '#475569' : '#94a3b8' }}>{value}</span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-400">Sin datos de distribución</div>
            )}
          </div>
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
