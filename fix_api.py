import os

with open("web/api.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Imports
content = content.replace(
    "from fastapi import FastAPI, BackgroundTasks, HTTPException, Form",
    "from fastapi import FastAPI, BackgroundTasks, HTTPException, Form, File, UploadFile"
)

# 2. run_scan_task
content = content.replace(
    "def run_scan_task(scan_id: str, url: str, deep_scan: bool, ssl_check: bool):",
    "def run_scan_task(scan_id: str, target: str, deep_scan: bool, ssl_check: bool, scan_type: str = \"url\"):"
)
content = content.replace(
    "scanner = APIScanner(url, deep_scan, ssl_check)",
    "scanner = APIScanner(target, deep_scan, ssl_check, scan_type=scan_type)"
)
# finally block for run_scan_task
old_finally = """        scans[scan_id]['status'] = 'failed'
        scans[scan_id]['message'] = f'Error: {str(e)}'
        scans[scan_id]['error'] = str(e)"""

new_finally = """        scans[scan_id]['status'] = 'failed'
        scans[scan_id]['message'] = f'Error: {str(e)}'
        scans[scan_id]['error'] = str(e)
    finally:
        if scan_type == "openapi" and os.path.exists(target):
            try:
                os.remove(target)
            except:
                pass"""
content = content.replace(old_finally, new_finally)

# 3. Add /api/scan/file endpoint after the normal /api/scan endpoint
old_scan_post = """    # Ejecutar en segundo plano
    background_tasks.add_task(run_scan_task, scan_id, url, deep_scan, ssl_check)
    
    return JSONResponse({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Escaneo iniciado correctamente'
    })"""

new_scan_post = """    # Ejecutar en segundo plano
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
    })"""
content = content.replace(old_scan_post, new_scan_post)

# 4. Remove global dashboard
content = content.replace("dashboard = TrendsDashboard(\"reports\")\n", "")

# 5. Add local dashboard to all dashboard endpoints
endpoints = [
    "def get_dashboard_summary():",
    "def get_dashboard_trends(days: int = 30):",
    "def get_frequent_vulnerabilities(limit: int = 5):",
    "def get_score_evolution(days: int = 30):",
    "def get_vulnerability_distribution():",
    "def get_url_analysis():",
    "def get_latest_scans(limit: int = 5):",
    "def get_daily_stats(days: int = 7):",
    "def get_full_dashboard(days: int = 30):",
    "def export_dashboard(days: int = 30):"
]
for ep in endpoints:
    content = content.replace(ep, ep + '\n    dashboard = TrendsDashboard("reports")')

with open("web/api.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Done")
