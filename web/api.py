# web/api.py (versión corregida)
"""
API Security Scanner - Servicio Web
Interfaz REST para la herramienta
"""

from backend.scaner import APIScanner
from fastapi import FastAPI, BackgroundTasks, HTTPException, Form, File, UploadFile, Header
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import uuid
import os
from datetime import datetime
import sys
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth
sys.path.append('..')

from backend.trends import TrendsDashboard


app = FastAPI(
    title="API Security Scanner",
    description="Herramienta automatizada para detección de vulnerabilidades en APIs",
    version="1.0.0"
)

# --- CONFIGURACIÓN CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4321", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURACIÓN FIREBASE ADMIN ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    cred = credentials.Certificate(os.path.join(BASE_DIR, "..", "firebase-credentials.json"))
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase Admin inicializado correctamente.")
except Exception as e:
    print(f"Advertencia: No se pudo inicializar Firebase Admin. Asegúrate de tener firebase-credentials.json en la raíz. Error: {e}")
    db = None

# Asegurar que exista la carpeta de reportes
os.makedirs("reports", exist_ok=True)

# Almacenamiento de escaneos (en memoria - para producción usar BD)
scans = {}

def run_scan_task(scan_id: str, target: str, deep_scan: bool, ssl_check: bool, scan_type: str = "url", user_id: str = None, auth_token: str = None):
    """Ejecuta el escaneo en segundo plano"""
    try:
        scanner = APIScanner(target, deep_scan, ssl_check, scan_type=scan_type, auth_token=auth_token)
        results = scanner.scan_all()
        
        # Añadir metadatos
        if user_id:
            results['user_id'] = user_id
            
        # Guardar resultados en memoria
        scans[scan_id]['results'] = results
        scans[scan_id]['status'] = 'completed'
        scans[scan_id]['completed_at'] = datetime.now().isoformat()
        scans[scan_id]['progress'] = 100
        scans[scan_id]['message'] = 'Escaneo completado'
        
        # Guardar en archivo local (backup)
        with open(f"reports/{scan_id}.json", "w") as f:
            json.dump(results, f, indent=2)
            
        # Guardar en Firestore
        if db:
            try:
                db.collection("reports").document(scan_id).set(results)
                print(f"Reporte {scan_id} guardado en Firestore.")
            except Exception as fb_err:
                print(f"Error guardando en Firestore: {fb_err}")
                
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

@app.get("/api/dashboard/full")
async def get_full_dashboard(days: int = 30, authorization: str = Header(None)):
    """Obtiene datos completos para el Dashboard (requiere auth)"""
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
        try:
            if firebase_admin.auth:
                decoded_token = firebase_auth.verify_id_token(token)
                user_id = decoded_token.get("uid")
        except:
            pass
            
    dashboard = TrendsDashboard(user_id=user_id)
    return JSONResponse(dashboard.get_full_dashboard(days=days))

@app.get("/api/history")
async def get_history(authorization: str = Header(None)):
    """Obtiene el historial de escaneos (requiere auth)"""
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
        try:
            if firebase_admin.auth:
                decoded_token = firebase_auth.verify_id_token(token)
                user_id = decoded_token.get("uid")
        except:
            pass
            
    dashboard = TrendsDashboard(user_id=user_id)
    history = dashboard.scans_data
    
    # Añadir conteos para la tabla
    for scan in history:
        summary = scan.get('summary', {}) or {}
        scan['critical_count'] = len(summary.get('critical', []) or [])
        scan['high_count'] = len(summary.get('high', []) or [])
        
    return JSONResponse(history)

@app.post("/api/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    url: str = Form(...),
    deep_scan: bool = Form(True),
    ssl_check: bool = Form(True),
    auth_token: str = Form(None),
    authorization: str = Header(None)
):
    """Inicia un escaneo de una API URL (requiere auth)"""
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
        try:
            decoded_token = firebase_auth.verify_id_token(token)
            user_id = decoded_token.get("uid")
        except Exception as e:
            print(f"Error de auth: {e}")
            
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        'id': scan_id,
        'target': url,
        'status': 'started',
        'started_at': datetime.now().isoformat(),
        'progress': 0,
        'message': 'Inicializando escáner',
        'type': 'url',
        'user_id': user_id
    }
    
    background_tasks.add_task(run_scan_task, scan_id, url, deep_scan, ssl_check, "url", user_id, auth_token)
    
    return JSONResponse({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Escaneo iniciado correctamente'
    })

@app.post("/api/scan/file")
async def start_scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    authorization: str = Header(None)
):
    """Sube un archivo OpenAPI y comienza el escaneo (requiere auth)"""
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
        try:
            decoded_token = firebase_auth.verify_id_token(token)
            user_id = decoded_token.get("uid")
        except:
            pass

    scan_id = str(uuid.uuid4())
    
    # Asegurar que uploads existe
    os.makedirs("uploads", exist_ok=True)
    file_path = f"uploads/{scan_id}_{file.filename}"
    
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
        
    scans[scan_id] = {
        'id': scan_id,
        'target': file.filename,
        'status': 'started',
        'started_at': datetime.now().isoformat(),
        'progress': 0,
        'message': 'Procesando archivo OpenAPI',
        'type': 'openapi',
        'user_id': user_id
    }
    
    background_tasks.add_task(run_scan_task, scan_id, file_path, False, False, "openapi", user_id)
    
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

# Los endpoints viejos de dashboard/history sin auth han sido eliminados para evitar colisiones.

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)