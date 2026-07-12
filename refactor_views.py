import os

# Create history.html
history_html = """{% extends "base.html" %}

{% block content %}
<section class="bg-white rounded-xl shadow-lg p-8 scan-card">
    <div class="flex justify-between items-center mb-6">
        <h2 class="text-2xl font-bold text-gray-800">📋 Historial de Escaneos</h2>
        <button onclick="loadHistory()" class="text-purple-600 hover:text-purple-800 font-medium flex items-center gap-2">
            <span>🔄</span> Actualizar
        </button>
    </div>
    <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
            <thead>
                <tr class="bg-gray-50 text-gray-600 text-sm border-b-2 border-gray-200">
                    <th class="p-4 font-semibold">Fecha</th>
                    <th class="p-4 font-semibold">URL Escaneada</th>
                    <th class="p-4 font-semibold text-center">Score</th>
                    <th class="p-4 font-semibold text-center">Críticas</th>
                    <th class="p-4 font-semibold text-center">Altas</th>
                    <th class="p-4 font-semibold text-center">Acciones</th>
                </tr>
            </thead>
            <tbody id="historyTableBody" class="text-sm">
                <tr>
                    <td colspan="6" class="p-8 text-center text-gray-500">
                        <div class="animate-pulse flex flex-col items-center">
                            <div class="h-8 w-8 bg-gray-200 rounded-full mb-4"></div>
                            <div class="h-4 w-32 bg-gray-200 rounded"></div>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

{% block extra_scripts %}
<script>
    async function loadHistory() {
        try {
            const response = await fetch('/api/history');
            const data = await response.json();
            
            const tbody = document.getElementById('historyTableBody');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="p-8 text-center text-gray-500">
                            No hay escaneos anteriores
                        </td>
                    </tr>
                `;
                return;
            }
            
            data.forEach(scan => {
                const date = new Date(scan.date).toLocaleString('es-ES');
                let scoreBadge = '';
                
                if (scan.score) {
                    const colorClass = `score-${scan.score.replace('+', 'plus')}`;
                    scoreBadge = `<span class="font-bold ${colorClass} text-lg">${scan.score}</span>`;
                } else {
                    scoreBadge = `<span class="text-gray-400">-</span>`;
                }
                
                tbody.innerHTML += `
                    <tr class="border-b border-gray-100 hover:bg-gray-50 transition-colors">
                        <td class="p-4 text-gray-600">${date}</td>
                        <td class="p-4 font-medium text-gray-800">${scan.url}</td>
                        <td class="p-4 text-center">${scoreBadge}</td>
                        <td class="p-4 text-center text-red-600 font-bold">${scan.critical_count || 0}</td>
                        <td class="p-4 text-center text-orange-500 font-bold">${scan.high_count || 0}</td>
                        <td class="p-4 text-center">
                            <a href="/reports/${scan.id}.json" download class="text-indigo-600 hover:text-indigo-800 bg-indigo-50 hover:bg-indigo-100 px-3 py-1 rounded-md transition-colors text-xs font-medium">
                                Descargar JSON
                            </a>
                        </td>
                    </tr>
                `;
            });
        } catch (error) {
            console.error('Error cargando historial:', error);
            const tbody = document.getElementById('historyTableBody');
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="p-8 text-center text-red-500">
                        Error al cargar el historial
                    </td>
                </tr>
            `;
        }
    }

    // Load history when page loads
    document.addEventListener("DOMContentLoaded", loadHistory);
</script>
{% endblock %}
"""

with open("web/templates/history.html", "w", encoding="utf-8") as f:
    f.write(history_html)

# Create dashboard.html
dashboard_html = """{% extends "base.html" %}

{% block extra_head %}
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
{% endblock %}

{% block content %}
<section class="bg-gray-50 rounded-xl p-2 mb-8">
    <div class="flex justify-between items-center mb-6 px-4">
        <h2 class="text-3xl font-bold text-gray-800">📊 Panel de Inteligencia de Seguridad</h2>
        <div class="flex gap-4">
            <select id="timeRange" onchange="loadDashboard()" class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-purple-500 focus:border-purple-500 block p-2.5 shadow-sm">
                <option value="7">Últimos 7 días</option>
                <option value="30" selected>Últimos 30 días</option>
                <option value="90">Últimos 90 días</option>
            </select>
            <button onclick="exportDashboard()" class="bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg text-sm px-4 py-2 text-center inline-flex items-center shadow-sm transition-colors">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                Exportar Reporte
            </button>
        </div>
    </div>

    <!-- KPI Cards -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8 px-2">
        <div class="bg-white rounded-xl shadow-sm p-6 border-l-4 border-purple-500 scan-card">
            <h3 class="text-sm font-medium text-gray-500 mb-1">Total de Escaneos</h3>
            <div class="text-3xl font-bold text-gray-800" id="dashTotalScans">0</div>
        </div>
        
        <div class="bg-white rounded-xl shadow-sm p-6 border-l-4 border-red-500 scan-card">
            <h3 class="text-sm font-medium text-gray-500 mb-1">Vulnerabilidades Críticas</h3>
            <div class="flex items-end gap-2">
                <div class="text-3xl font-bold text-gray-800" id="dashCriticalVulns">0</div>
                <span class="text-sm text-red-500 mb-1 font-medium" id="dashCriticalTrend"></span>
            </div>
        </div>

        <div class="bg-white rounded-xl shadow-sm p-6 border-l-4 border-green-500 scan-card">
            <h3 class="text-sm font-medium text-gray-500 mb-1">Score Promedio</h3>
            <div class="text-3xl font-bold text-gray-800" id="dashAvgScore">N/A</div>
        </div>

        <div class="bg-white rounded-xl shadow-sm p-6 border-l-4 border-blue-500 scan-card">
            <h3 class="text-sm font-medium text-gray-500 mb-1">APIs Analizadas</h3>
            <div class="text-3xl font-bold text-gray-800" id="dashUniqueUrls">0</div>
        </div>
    </div>

    <!-- Charts Row 1 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8 px-2">
        <!-- Tendencias a lo largo del tiempo -->
        <div class="bg-white rounded-xl shadow-sm p-6 lg:col-span-2 scan-card">
            <h3 class="text-lg font-bold text-gray-800 mb-4">Evolución de Vulnerabilidades</h3>
            <div class="relative h-72">
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <!-- Distribución de Severidad -->
        <div class="bg-white rounded-xl shadow-sm p-6 scan-card">
            <h3 class="text-lg font-bold text-gray-800 mb-4">Distribución por Severidad</h3>
            <div class="relative h-72">
                <canvas id="distributionChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Row 2 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 px-2">
        <!-- Top Vulnerabilidades -->
        <div class="bg-white rounded-xl shadow-sm p-6 scan-card">
            <h3 class="text-lg font-bold text-gray-800 mb-4">Vulnerabilidades más Frecuentes</h3>
            <div class="overflow-y-auto max-h-80 pr-2" id="frequentVulnsList">
                <!-- Se llena con JS -->
            </div>
        </div>

        <!-- Estado de APIs -->
        <div class="bg-white rounded-xl shadow-sm p-6 scan-card">
            <h3 class="text-lg font-bold text-gray-800 mb-4">Estado por API (Top 5 con más riesgos)</h3>
            <div class="overflow-y-auto max-h-80 pr-2" id="apiRiskList">
                <!-- Se llena con JS -->
            </div>
        </div>
    </div>
</section>
{% endblock %}

{% block extra_scripts %}
<script>
    let trendChartInstance = null;
    let distChartInstance = null;
    
    // Configuración global de Chart.js
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = '#6b7280';
    
    async function loadDashboard() {
        const days = document.getElementById('timeRange').value;
        
        try {
            // Cargar datos del dashboard completo
            const response = await fetch(`/api/dashboard/full?days=${days}`);
            const data = await response.json();
            
            // 1. Actualizar KPIs
            document.getElementById('dashTotalScans').innerText = data.stats.total_scans;
            document.getElementById('dashCriticalVulns').innerText = data.stats.total_critical;
            document.getElementById('dashAvgScore').innerText = data.stats.avg_score;
            document.getElementById('dashAvgScore').className = `text-3xl font-bold score-${data.stats.avg_score.replace('+', 'plus')}`;
            document.getElementById('dashUniqueUrls').innerText = data.stats.unique_urls;
            
            // 2. Renderizar Gráfica de Tendencias (Evolución)
            const trendCtx = document.getElementById('trendChart').getContext('2d');
            
            if (trendChartInstance) {
                trendChartInstance.destroy();
            }
            
            trendChartInstance = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: data.trends.dates,
                    datasets: [
                        {
                            label: 'Críticas',
                            data: data.trends.critical,
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            fill: true,
                            tension: 0.4
                        },
                        {
                            label: 'Altas',
                            data: data.trends.high,
                            borderColor: '#f97316',
                            backgroundColor: 'rgba(249, 115, 22, 0.1)',
                            fill: true,
                            tension: 0.4
                        },
                        {
                            label: 'Medias',
                            data: data.trends.medium,
                            borderColor: '#eab308',
                            backgroundColor: 'rgba(234, 179, 8, 0.1)',
                            fill: true,
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    },
                    scales: {
                        y: { beginAtZero: true, grid: { borderDash: [2, 4] } },
                        x: { grid: { display: false } }
                    }
                }
            });
            
            // 3. Renderizar Gráfica de Distribución
            const distCtx = document.getElementById('distributionChart').getContext('2d');
            
            if (distChartInstance) {
                distChartInstance.destroy();
            }
            
            const distData = data.distribution;
            
            distChartInstance = new Chart(distCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Críticas', 'Altas', 'Medias', 'Bajas/Info'],
                    datasets: [{
                        data: [
                            distData.critical, 
                            distData.high, 
                            distData.medium, 
                            distData.low
                        ],
                        backgroundColor: [
                            '#ef4444', '#f97316', '#eab308', '#3b82f6'
                        ],
                        borderWidth: 0,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
            
            // 4. Llenar lista de Vulnerabilidades Frecuentes
            const vulnsList = document.getElementById('frequentVulnsList');
            vulnsList.innerHTML = '';
            
            if (data.frequent_vulns && data.frequent_vulns.length > 0) {
                data.frequent_vulns.forEach(vuln => {
                    let severityColor = 'bg-gray-100 text-gray-800';
                    if (vuln.severity === 'critical') severityColor = 'bg-red-100 text-red-800';
                    if (vuln.severity === 'high') severityColor = 'bg-orange-100 text-orange-800';
                    if (vuln.severity === 'medium') severityColor = 'bg-yellow-100 text-yellow-800';
                    
                    vulnsList.innerHTML += `
                        <div class="mb-4 pb-4 border-b border-gray-100 last:border-0 last:pb-0 last:mb-0 flex justify-between items-center">
                            <div class="pr-4">
                                <h4 class="font-semibold text-gray-800 text-sm truncate" title="${vuln.title}">${vuln.title}</h4>
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${severityColor} mt-1">
                                    ${vuln.severity.toUpperCase()}
                                </span>
                            </div>
                            <div class="text-right flex-shrink-0">
                                <div class="text-lg font-bold text-gray-700">${vuln.count}</div>
                                <div class="text-xs text-gray-500">veces</div>
                            </div>
                        </div>
                    `;
                });
            } else {
                vulnsList.innerHTML = '<p class="text-gray-500 text-center py-8">No hay datos suficientes</p>';
            }
            
            // 5. Llenar lista de Riesgos por API
            const apiList = document.getElementById('apiRiskList');
            apiList.innerHTML = '';
            
            // Ordenar APIs por puntaje de riesgo (asumiendo que D > C > B > A)
            // Simplificado: ordenamos por total de problemas
            const sortedApis = (data.urls || []).sort((a, b) => b.total_issues - a.total_issues).slice(0, 5);
            
            if (sortedApis.length > 0) {
                sortedApis.forEach(api => {
                    // Calcular un porcentaje de riesgo visual (0-100%)
                    // Máximo arbitrario de 20 problemas para la barra 100%
                    const riskPercentage = Math.min((api.total_issues / 20) * 100, 100);
                    let barColor = 'bg-green-500';
                    
                    if (api.critical_issues > 0) barColor = 'bg-red-500';
                    else if (api.high_issues > 0) barColor = 'bg-orange-500';
                    else if (api.medium_issues > 0) barColor = 'bg-yellow-500';
                    
                    apiList.innerHTML += `
                        <div class="mb-4 pb-4 border-b border-gray-100 last:border-0 last:pb-0 last:mb-0">
                            <div class="flex justify-between items-end mb-1">
                                <span class="font-medium text-sm text-gray-800 truncate pr-4" title="${api.url}">${api.url}</span>
                                <span class="text-xs font-bold text-gray-600">${api.total_issues} issues</span>
                            </div>
                            <div class="w-full bg-gray-200 rounded-full h-1.5 mb-1">
                                <div class="${barColor} h-1.5 rounded-full" style="width: ${riskPercentage}%"></div>
                            </div>
                            <div class="flex justify-between text-xs text-gray-500 mt-1">
                                <span><span class="text-red-500 font-bold">${api.critical_issues}</span> Críticas</span>
                                <span><span class="text-orange-500 font-bold">${api.high_issues}</span> Altas</span>
                            </div>
                        </div>
                    `;
                });
            } else {
                apiList.innerHTML = '<p class="text-gray-500 text-center py-8">No hay APIs analizadas</p>';
            }
            
        } catch (error) {
            console.error('Error cargando el dashboard:', error);
        }
    }

    async function exportDashboard() {
        const days = document.getElementById('timeRange').value;
        window.location.href = `/api/dashboard/export?days=${days}`;
    }

    // Load dashboard on page load
    document.addEventListener("DOMContentLoaded", loadDashboard);
</script>
{% endblock %}
"""

with open("web/templates/dashboard.html", "w", encoding="utf-8") as f:
    f.write(dashboard_html)
