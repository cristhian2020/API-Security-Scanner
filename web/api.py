# web/api.py (versión corregida)
"""
API Security Scanner - Servicio Web
Interfaz REST para la herramienta
"""

from backend.scaner import APIScanner
from fastapi import FastAPI, BackgroundTasks, HTTPException, Form, File, UploadFile
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
import json
import uuid
import os
from datetime import datetime
import sys
sys.path.append('..')

from backend.trends import TrendsDashboard


app = FastAPI(
    title="API Security Scanner",
    description="Herramienta automatizada para detección de vulnerabilidades en APIs",
    version="1.0.0"
)

# --- CONFIGURACIÓN CORREGIDA ---
# Obtener la ruta absoluta del directorio actual
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Crear directorios si no existen
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Configurar templates con la ruta correcta
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Montar archivos estáticos
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Asegurar que exista la carpeta de reportes
os.makedirs("reports", exist_ok=True)

# Almacenamiento de escaneos (en memoria - para producción usar BD)
scans = {}

def run_scan_task(scan_id: str, target: str, deep_scan: bool, ssl_check: bool, scan_type: str = "url"):
    """Ejecuta el escaneo en segundo plano"""
    try:
        scanner = APIScanner(target, deep_scan, ssl_check, scan_type=scan_type)
        results = scanner.scan_all()
        
        # Guardar resultados
        scans[scan_id]['results'] = results
        scans[scan_id]['status'] = 'completed'
        scans[scan_id]['completed_at'] = datetime.now().isoformat()
        scans[scan_id]['progress'] = 100
        scans[scan_id]['message'] = 'Escaneo completado'
        
        # Guardar en archivo
        with open(f"reports/{scan_id}.json", "w") as f:
            json.dump(results, f, indent=2)
            
    except Exception as e:
        scans[scan_id]['status'] = 'failed'
        scans[scan_id]['message'] = f'Error: {str(e)}'
        scans[scan_id]['error'] = str(e)
    finally:
        if scan_type == "openapi" and os.path.exists(target):
            try:
                os.remove(target)
            except:
                pass

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Página principal"""
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Página del Dashboard"""
    return templates.TemplateResponse(request=request, name="dashboard.html")

@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    """Página del Historial"""
    return templates.TemplateResponse(request=request, name="history.html")

@app.post("/api/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    url: str = Form(...),
    deep_scan: bool = Form(True),
    ssl_check: bool = Form(True)
):
    """Inicia un nuevo escaneo"""
    # Validar URL
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    scan_id = str(uuid.uuid4())
    
    scans[scan_id] = {
        'id': scan_id,
        'url': url,
        'status': 'running',
        'progress': 0,
        'message': 'Iniciando escaneo...',
        'started_at': datetime.now().isoformat(),
        'completed_at': None,
        'results': None,
        'error': None
    }
    
    # Ejecutar en segundo plano
    background_tasks.add_task(run_scan_task, scan_id, url, deep_scan, ssl_check, "url")
    
    return JSONResponse({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Escaneo iniciado correctamente'
    })

@app.post("/api/scan/file")
async def start_scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    scan_id = str(uuid.uuid4())
    os.makedirs("uploads", exist_ok=True)
    file_path = os.path.join("uploads", f"{scan_id}_{file.filename}")
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
        
    scans[scan_id] = {
        'id': scan_id,
        'url': f"Archivo OpenAPI: {file.filename}",
        'status': 'running',
        'progress': 0,
        'message': 'Iniciando escaneo de OpenAPI...',
        'started_at': datetime.now().isoformat(),
        'completed_at': None,
        'results': None,
        'error': None
    }
    
    background_tasks.add_task(run_scan_task, scan_id, file_path, False, False, "openapi")
    
    return JSONResponse({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Escaneo de archivo iniciado correctamente'
    })

@app.get("/api/status/{scan_id}")
async def get_status(scan_id: str):
    """Obtiene el estado de un escaneo"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    
    return {
        'status': scan['status'],
        'progress': scan.get('progress', 0),
        'message': scan.get('message', 'Escaneando...'),
        'error': scan.get('error')
    }

@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    """Obtiene el reporte completo"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    if scan['status'] != 'completed' or not scan['results']:
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    return JSONResponse(scan['results'])

@app.get("/api/download/{scan_id}")
async def download_report(scan_id: str, format: str = "json"):
    """Descarga el reporte en diferentes formatos"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    if scan['status'] != 'completed' or not scan['results']:
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    filename = f"report_{scan_id}.{format}"
    filepath = os.path.join("reports", filename)
    
    if format == "json":
        with open(filepath, "w") as f:
            json.dump(scan['results'], f, indent=2)
        return FileResponse(filepath, media_type="application/json", filename=filename)
    elif format == "html":
        # Generar HTML simple
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Reporte de Seguridad</title></head>
        <body>
            <h1>Reporte de Seguridad - API Security Scanner</h1>
            <p><strong>URL:</strong> {scan['results']['url']}</p>
            <p><strong>Puntuación:</strong> {scan['results']['score']}</p>
            <h2>Vulnerabilidades encontradas:</h2>
            <ul>
        """
        for v in scan['results']['vulnerabilities']:
            html_content += f"<li><strong>{v['title']}</strong> - {v['severity']}</li>"
        html_content += "</ul></body></html>"
        
        with open(filepath, "w", encoding='utf-8') as f:
            f.write(html_content)
        return FileResponse(filepath, media_type="text/html", filename=filename)
    
    raise HTTPException(status_code=400, detail="Format not supported")

@app.get("/api/health")
async def health_check():
    """Verifica que el servicio esté funcionando"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/history")
async def get_history():
    """Obtiene el historial de escaneos"""
    history = []
    for scan_id, scan in scans.items():
        history.append({
            'id': scan_id,
            'url': scan['url'],
            'status': scan['status'],
            'score': scan['results']['score'] if scan['results'] else None,
            'started_at': scan['started_at']
        })
    return JSONResponse(history)

@app.get("/api/dashboard/summary")
async def get_dashboard_summary():
    dashboard = TrendsDashboard("reports")
    """Obtiene estadísticas generales del dashboard"""
    return JSONResponse(dashboard.get_summary_stats())

@app.get("/api/dashboard/trends")
async def get_dashboard_trends(days: int = 30):
    dashboard = TrendsDashboard("reports")
    """Obtiene tendencias por severidad"""
    return JSONResponse(dashboard.get_trend_by_severity(days))

@app.get("/api/dashboard/frequent")
async def get_frequent_vulnerabilities(limit: int = 10):
    """Obtiene las vulnerabilidades más frecuentes"""
    dashboard = TrendsDashboard("reports")
    return JSONResponse(dashboard.get_frequent_vulnerabilities(limit))

@app.get("/api/dashboard/evolution")
async def get_score_evolution(days: int = 30):
    dashboard = TrendsDashboard("reports")
    """Obtiene evolución de puntuación"""
    return JSONResponse(dashboard.get_score_evolution(days))

@app.get("/api/dashboard/distribution")
async def get_vulnerability_distribution():
    dashboard = TrendsDashboard("reports")
    """Obtiene distribución de vulnerabilidades"""
    return JSONResponse(dashboard.get_vulnerability_distribution())

@app.get("/api/dashboard/urls")
async def get_url_analysis():
    dashboard = TrendsDashboard("reports")
    """Obtiene análisis por URL"""
    return JSONResponse(dashboard.get_url_analysis())

@app.get("/api/dashboard/daily")
async def get_daily_stats(days: int = 7):
    dashboard = TrendsDashboard("reports")
    """Obtiene estadísticas diarias"""
    return JSONResponse(dashboard.get_daily_stats(days))

@app.get("/api/dashboard/full")
async def get_full_dashboard(days: int = 30):
    dashboard = TrendsDashboard("reports")
    """Obtiene dashboard completo"""
    return JSONResponse(dashboard.get_full_dashboard(days))

@app.get("/api/dashboard/export")
async def export_dashboard():
    """Exporta dashboard a JSON"""
    dashboard = TrendsDashboard("reports")
    if dashboard.export_to_json("dashboard_export.json"):
        return FileResponse("dashboard_export.json", media_type="application/json", filename="dashboard_export.json")
    return JSONResponse({"error": "Error al exportar"}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)