import os

with open("web/templates/index.html", "r", encoding="utf-8") as f:
    content = f.read()

# Base HTML
base_html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Scanner - DevSecOps Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    {% block extra_head %}{% endblock %}
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        * { font-family: 'Inter', sans-serif; }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .scan-card { transition: all 0.3s ease; }
        .scan-card:hover { transform: translateY(-2px); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); }
        .severity-critical { border-left-color: #ef4444; }
        .severity-high { border-left-color: #f97316; }
        .severity-medium { border-left-color: #eab308; }
        .severity-low { border-left-color: #3b82f6; }
        .severity-info { border-left-color: #9ca3af; }
        .badge-critical { background: #fecaca; color: #991b1b; }
        .badge-high { background: #fed7aa; color: #9a3412; }
        .badge-medium { background: #fef9c3; color: #854d0e; }
        .badge-low { background: #bfdbfe; color: #1e40af; }
        .badge-info { background: #e5e7eb; color: #374151; }
        .score-Aplus { color: #22c55e; }
        .score-A { color: #22c55e; }
        .score-B { color: #eab308; }
        .score-C { color: #f97316; }
        .score-D { color: #ef4444; }
        .code-block {
            background: #1e1e2e; color: #cdd6f4; padding: 1rem;
            border-radius: 0.5rem; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.875rem;
        }
        {% block extra_css %}{% endblock %}
    </style>
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <header class="gradient-bg text-white shadow-lg">
        <div class="container mx-auto px-6 py-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold"><a href="/">🔒 API Security Scanner</a></h1>
                    <p class="text-purple-100 mt-1">Detecta y corrige vulnerabilidades en tus APIs</p>
                </div>
                <div class="flex items-center gap-4">
                    <span class="bg-white/20 px-4 py-2 rounded-lg text-sm">v1.0.0</span>
                    <a href="/" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-lg transition-all text-sm">
                        🚀 Escanear
                    </a>
                    <a href="/history" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-lg transition-all text-sm">
                        📋 Historial
                    </a>
                    <a href="/dashboard" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-lg transition-all text-sm">
                        📊 Dashboard
                    </a>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="container mx-auto px-6 py-8">
        {% block content %}{% endblock %}
    </main>

    {% block extra_scripts %}{% endblock %}
</body>
</html>
"""
with open("web/templates/base.html", "w", encoding="utf-8") as f:
    f.write(base_html)

# Now we need to extract index.html parts.
# Fortunately, I can just use a simplified version of index.html that inherits base.html

index_html = """{% extends "base.html" %}

{% block extra_css %}
        #progress-bar { transition: width 0.5s ease; }
        .pulse-animation { animation: pulse 1.5s ease-in-out infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .fade-in { animation: fadeIn 0.5s ease-in; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
{% endblock %}

{% block content %}
        <!-- Sección de entrada -->
        <section class="bg-white rounded-xl shadow-lg p-8 mb-8 scan-card">
            <h2 class="text-2xl font-bold text-gray-800 mb-2">🔍 Escanea tu API</h2>
            <p class="text-gray-600 mb-6">Ingresa la URL de tu API para analizar su seguridad automáticamente</p>
            
            <form id="scanForm" onsubmit="startScan(event)">
                <div class="flex gap-4 mb-4">
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="radio" name="scanMode" value="url" checked onchange="toggleScanMode()" class="text-purple-600 focus:ring-purple-500">
                        <span class="text-sm font-medium">Escanear URL</span>
                    </label>
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input type="radio" name="scanMode" value="openapi" onchange="toggleScanMode()" class="text-purple-600 focus:ring-purple-500">
                        <span class="text-sm font-medium">Subir OpenAPI (Swagger)</span>
                    </label>
                </div>

                <div class="flex flex-col md:flex-row gap-4" id="urlInputGroup">
                    <input type="url" id="urlInput" placeholder="https://api.tudominio.com/v1" class="flex-1 p-4 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all">
                </div>

                <div class="flex flex-col md:flex-row gap-4 hidden" id="fileInputGroup">
                    <input type="file" id="fileInput" accept=".json,.yaml,.yml" class="flex-1 p-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all bg-gray-50">
                </div>

                <div class="mt-4 flex">
                    <button type="submit" id="scanButton" class="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white px-8 py-4 rounded-xl font-semibold transition-all flex items-center justify-center gap-2 w-full md:w-auto">
                        <span>🚀</span>
                        <span>Iniciar Escaneo</span>
                    </button>
                </div>
                
                <details class="mt-4" id="advancedOptionsDetails">
                    <summary class="text-sm text-gray-500 cursor-pointer hover:text-gray-700">⚙️ Opciones avanzadas</summary>
                    <div class="mt-4 p-4 bg-gray-50 rounded-xl border border-gray-200">
                        <label class="flex items-center gap-3 text-sm">
                            <input type="checkbox" id="deepScan" checked class="rounded text-purple-600 focus:ring-purple-500">
                            <span class="font-medium text-gray-700">Escaneo profundo (Deep Scan)</span>
                        </label>
                        <p class="text-xs text-gray-500 ml-7 mt-1">Activa pruebas activas como Fuzzing (SQL Inyection) y Rate Limiting.</p>
                        <label class="flex items-center gap-3 text-sm mt-3">
                            <input type="checkbox" id="sslCheck" checked class="rounded text-purple-600 focus:ring-purple-500">
                            <span class="font-medium text-gray-700">Verificar certificado SSL/TLS</span>
                        </label>
                    </div>
                </details>
            </form>
        </section>

        <!-- Progress Section -->
        <section id="progressSection" class="hidden fade-in bg-white rounded-xl shadow-lg p-8 mb-8">
            <div class="flex justify-between items-center mb-4">
                <h3 class="font-semibold text-lg" id="statusText">Iniciando escáner...</h3>
                <span class="text-purple-600 font-bold" id="progressText">0%</span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-3">
                <div id="progressBar" class="gradient-bg h-3 rounded-full" style="width: 0%"></div>
            </div>
        </section>

        <!-- Results Section -->
        <section id="resultsSection" class="hidden fade-in">
            <!-- Puntuación Global -->
            <div class="bg-white rounded-xl shadow-lg p-8 mb-8 flex items-center justify-between">
                <div>
                    <h2 class="text-2xl font-bold text-gray-800 mb-2">Puntuación de Seguridad</h2>
                    <p class="text-gray-600">Basado en estándares CVSS y OWASP API Security Top 10</p>
                </div>
                <div class="text-6xl font-bold" id="scoreDisplay">
                    <!-- Se llena con JS -->
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <!-- Tarjetas de resumen -->
                <div class="bg-white p-6 rounded-xl shadow-sm border border-red-100 scan-card">
                    <div class="text-red-500 font-semibold mb-1">Críticas</div>
                    <div class="text-3xl font-bold text-red-600" id="criticalCount">0</div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-orange-100 scan-card">
                    <div class="text-orange-500 font-semibold mb-1">Altas</div>
                    <div class="text-3xl font-bold text-orange-600" id="highCount">0</div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-yellow-100 scan-card">
                    <div class="text-yellow-500 font-semibold mb-1">Medias</div>
                    <div class="text-3xl font-bold text-yellow-600" id="mediumCount">0</div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-blue-100 scan-card">
                    <div class="text-blue-500 font-semibold mb-1">Seguras</div>
                    <div class="text-3xl font-bold text-blue-600" id="secureCount">0</div>
                </div>
            </div>

            <!-- Lista de Vulnerabilidades -->
            <div class="bg-white rounded-xl shadow-lg p-8">
                <h3 class="text-xl font-bold text-gray-800 mb-6">Hallazgos Detallados</h3>
                <div id="vulnerabilitiesList" class="space-y-4">
                    <!-- Los resultados se inyectan aquí -->
                </div>
            </div>
        </section>
{% endblock %}

{% block extra_scripts %}
    <script>
        let currentScanId = null;
        let monitoringInterval = null;
        
        function toggleScanMode() {
            const mode = document.querySelector('input[name="scanMode"]:checked').value;
            if (mode === 'url') {
                document.getElementById('urlInputGroup').classList.remove('hidden');
                document.getElementById('fileInputGroup').classList.add('hidden');
                document.getElementById('urlInput').required = true;
                document.getElementById('fileInput').required = false;
                document.getElementById('advancedOptionsDetails').classList.remove('hidden');
            } else {
                document.getElementById('urlInputGroup').classList.add('hidden');
                document.getElementById('fileInputGroup').classList.remove('hidden');
                document.getElementById('urlInput').required = false;
                document.getElementById('fileInput').required = true;
                document.getElementById('advancedOptionsDetails').classList.add('hidden');
            }
        }

        async function startScan(event) {
            event.preventDefault();
            
            const mode = document.querySelector('input[name="scanMode"]:checked').value;
            const url = document.getElementById('urlInput').value.trim();
            const fileInput = document.getElementById('fileInput');
            
            if (mode === 'url' && !url) {
                alert('⚠️ Por favor, ingresa una URL válida');
                return;
            }
            if (mode === 'openapi' && (!fileInput.files || fileInput.files.length === 0)) {
                alert('⚠️ Por favor, sube un archivo OpenAPI (.json o .yaml)');
                return;
            }
            
            const deepScan = document.getElementById('deepScan').checked;
            const sslCheck = document.getElementById('sslCheck').checked;
            
            document.getElementById('progressSection').classList.remove('hidden');
            document.getElementById('resultsSection').classList.add('hidden');
            
            const scanButton = document.getElementById('scanButton');
            scanButton.disabled = true;
            scanButton.innerHTML = '⏳ Escaneando...';
            
            try {
                const formData = new FormData();
                let endpoint = '/api/scan';
                
                if (mode === 'url') {
                    formData.append('url', url);
                    formData.append('deep_scan', deepScan);
                    formData.append('ssl_check', sslCheck);
                } else {
                    formData.append('file', fileInput.files[0]);
                    endpoint = '/api/scan/file';
                }
                
                const response = await fetch(endpoint, {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.status === 'started') {
                    currentScanId = data.scan_id;
                    monitorProgress();
                }
            } catch (error) {
                alert('Error al iniciar el escaneo');
                scanButton.disabled = false;
                scanButton.innerHTML = '🚀 Iniciar Escaneo';
            }
        }

        async function monitorProgress() {
            monitoringInterval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/status/${currentScanId}`);
                    const data = await response.json();
                    
                    document.getElementById('progressBar').style.width = `${data.progress}%`;
                    document.getElementById('progressText').innerText = `${data.progress}%`;
                    document.getElementById('statusText').innerText = data.message;
                    
                    if (data.status === 'completed') {
                        clearInterval(monitoringInterval);
                        loadResults();
                    } else if (data.status === 'failed') {
                        clearInterval(monitoringInterval);
                        alert('Error: ' + data.error);
                        resetButton();
                    }
                } catch (error) {
                    console.error('Error monitoreando progreso:', error);
                }
            }, 1000);
        }

        async function loadResults() {
            try {
                const response = await fetch(`/api/report/${currentScanId}`);
                const data = await response.json();
                
                document.getElementById('progressSection').classList.add('hidden');
                document.getElementById('resultsSection').classList.remove('hidden');
                resetButton();
                
                const scoreDisplay = document.getElementById('scoreDisplay');
                scoreDisplay.innerText = data.score;
                scoreDisplay.className = `text-6xl font-bold score-${data.score.replace('+', 'plus')}`;
                
                let criticalCount = data.critical_count || 0;
                let highCount = data.summary.high ? data.summary.high.length : 0;
                let medCount = data.summary.medium ? data.summary.medium.length : 0;
                
                document.getElementById('criticalCount').innerText = criticalCount;
                document.getElementById('highCount').innerText = highCount;
                document.getElementById('mediumCount').innerText = data.medium_count || medCount;
                document.getElementById('secureCount').innerText = data.secure_count || 0;
                
                const list = document.getElementById('vulnerabilitiesList');
                list.innerHTML = '';
                
                if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
                    list.innerHTML = `
                        <div class="bg-green-50 border-l-4 border-green-500 p-6 rounded-r-lg">
                            <h4 class="text-green-800 font-bold text-lg mb-2">✅ ¡No se encontraron vulnerabilidades!</h4>
                            <p class="text-green-700">Tu API tiene una configuración de seguridad excelente.</p>
                        </div>
                    `;
                    return;
                }
                
                data.vulnerabilities.forEach(vuln => {
                    let badgeClass = '';
                    let badgeText = '';
                    
                    switch(vuln.severity) {
                        case 'critical': badgeClass = 'badge-critical'; badgeText = 'CRÍTICO'; break;
                        case 'high': badgeClass = 'badge-high'; badgeText = 'ALTO'; break;
                        case 'medium': badgeClass = 'badge-medium'; badgeText = 'MEDIO'; break;
                        case 'low': badgeClass = 'badge-low'; badgeText = 'BAJO'; break;
                        default: badgeClass = 'badge-info'; badgeText = 'INFO';
                    }
                    
                    list.innerHTML += `
                        <div class="border-l-4 p-6 bg-gray-50 rounded-r-xl severity-${vuln.severity} mb-4">
                            <div class="flex items-center justify-between mb-2">
                                <h4 class="font-bold text-lg text-gray-800">${vuln.title}</h4>
                                <span class="px-3 py-1 rounded-full text-xs font-bold ${badgeClass}">${badgeText}</span>
                            </div>
                            <p class="text-gray-600 mb-4">${vuln.description}</p>
                            
                            <div class="grid md:grid-cols-2 gap-4 mt-4">
                                <div class="bg-white p-4 rounded-lg border border-red-100">
                                    <h5 class="font-bold text-red-800 text-sm mb-1">💥 Impacto:</h5>
                                    <p class="text-sm text-gray-700">${vuln.impact}</p>
                                </div>
                                <div class="bg-white p-4 rounded-lg border border-green-100">
                                    <h5 class="font-bold text-green-800 text-sm mb-1">📝 Recomendación:</h5>
                                    <p class="text-sm text-gray-700">${vuln.recommendation}</p>
                                </div>
                            </div>
                            
                            ${vuln.code_example ? `
                            <div class="mt-4">
                                <h5 class="font-semibold text-gray-700 text-sm mb-2">Ejemplo de solución:</h5>
                                <div class="code-block">${vuln.code_example.replace(/\\n/g, '<br>').replace(/ /g, '&nbsp;')}</div>
                            </div>` : ''}
                            
                            ${vuln.link ? `
                            <div class="mt-4 text-right">
                                <a href="${vuln.link}" target="_blank" class="text-purple-600 hover:text-purple-800 text-sm font-medium flex items-center justify-end gap-1">
                                    💡 Ver cómo solucionarlo
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                                </a>
                            </div>` : ''}
                        </div>
                    `;
                });
                
            } catch (error) {
                console.error('Error cargando resultados:', error);
            }
        }

        function resetButton() {
            const scanButton = document.getElementById('scanButton');
            scanButton.disabled = false;
            scanButton.innerHTML = `<span>🚀</span><span>Iniciar Escaneo</span>`;
        }
    </script>
{% endblock %}
"""
with open("web/templates/index.html", "w", encoding="utf-8") as f:
    f.write(index_html)
