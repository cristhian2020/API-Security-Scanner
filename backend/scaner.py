# backend/scanner.py
"""
API Security Scanner - Módulo de Escaneo (Motor VULNAPI)
Base para la aplicación web y CLI
"""

import subprocess
import json
import time
import uuid
import os
import re
from typing import Dict, List, Optional
from datetime import datetime

# Mapeo de vulnerabilidades de VulnAPI a formato enriquecido en español
VULNAPI_ISSUES_MAP = {
    "discover.fingerprint": {
        "title": "Exposición de información del servidor (Fingerprinting)",
        "severity": "info",
        "description": "Se detectó la identidad o versión del servidor web/framework mediante cabeceras HTTP u otras firmas.",
        "impact": "Un atacante puede identificar versiones específicas de software y buscar vulnerabilidades conocidas (CVEs) para ese componente.",
        "recommendation": "Oculta o personaliza las cabeceras de respuesta del servidor (Server, X-Powered-By) en la configuración de producción.",
        "code_example": """# En Nginx:
server_tokens off;

# En Apache:
ServerTokens Prod
ServerSignature Off""",
        "link": "https://owasp.org/www-project-secure-headers/#server"
    },
    "discover.server_signature": {
        "title": "Exposición de información del servidor (Firma de Servidor)",
        "severity": "info",
        "description": "El servidor web revela información detallada sobre su software y versión en sus respuestas.",
        "impact": "Permite a los atacantes realizar un reconocimiento más preciso para explotar debilidades específicas.",
        "recommendation": "Configura el servidor web para desactivar o limitar las firmas en las respuestas HTTP.",
        "code_example": """# En Nginx:
server_tokens off;

# En Apache:
ServerTokens Prod
ServerSignature Off""",
        "link": "https://owasp.org/www-project-secure-headers/#server"
    },
    "discover.accept_unauthenticated_operation": {
        "title": "Operación permite acceso no autenticado",
        "severity": "info",
        "description": "La API acepta peticiones en este endpoint sin requerir cabeceras o tokens de autenticación.",
        "impact": "Si el endpoint maneja datos sensibles o acciones críticas, podría permitir el acceso no autorizado.",
        "recommendation": "Asegura el endpoint implementando autenticación (OAuth2, JWT, API Keys) si contiene lógica o datos restringidos.",
        "code_example": """# En FastAPI - Requerir autenticación
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/items/")
async def read_items(token: str = Depends(oauth2_scheme)):
    return {"token": token}""",
        "link": "https://owasp.org/www-project-api-security-top-10/#api2-2023-broken-authentication"
    },
    "broken_authentication.authentication_bypass": {
        "title": "Bypass de autenticación detectado",
        "severity": "critical",
        "description": "La API permite omitir o saltarse los controles de autenticación esperados.",
        "impact": "Acceso total no autorizado a recursos protegidos y datos de usuarios.",
        "recommendation": "Verifica rigurosamente todas las rutas protegidas y asegura que no admitan derivaciones mediante métodos HTTP alternativos o parámetros maliciosos.",
        "code_example": """# Asegura que los decoradores o middleware de seguridad se apliquen a todas las rutas protegidas de manera estricta y sin excepciones no controladas.""",
        "link": "https://owasp.org/www-project-api-security-top-10/#api2-2023-broken-authentication"
    },
    "security_misconfiguration.http_headers_content_options_missing": {
        "title": "Header X-Content-Type-Options faltante",
        "severity": "medium",
        "description": "El header X-Content-Type-Options no está configurado en las respuestas de la API.",
        "impact": "Podría permitir que el navegador realice MIME-sniffing, interpretando respuestas como scripts ejecutables, lo que facilita ataques XSS.",
        "recommendation": "Configura la cabecera 'X-Content-Type-Options: nosniff' en todas las respuestas.",
        "code_example": """# En FastAPI - Agregar header en middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response""",
        "link": "https://owasp.org/www-project-secure-headers/#x-content-type-options"
    },
    "security_misconfiguration.http_headers_cors_wildcard": {
        "title": "CORS permite cualquier origen (*)",
        "severity": "high",
        "description": "CORS está configurado con '*' permitiendo que cualquier sitio web externo acceda a los recursos de tu API.",
        "impact": "Un atacante puede alojar un sitio web malicioso que realice peticiones no deseadas a tu API en nombre de un usuario autenticado.",
        "recommendation": "Restringe CORS a dominios específicos y de confianza. Nunca utilices '*' si manejas credenciales o datos de sesión.",
        "code_example": """# En FastAPI - Configuración segura de CORS
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://tu-sitio-seguro.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)""",
        "link": "https://owasp.org/www-project-secure-headers/#cross-origin-resource-sharing"
    },
    "security_misconfiguration.http_headers_csp_frame_ancestors_missing": {
        "title": "Directiva CSP frame-ancestors faltante",
        "severity": "medium",
        "description": "La política Content-Security-Policy (CSP) no define la directiva frame-ancestors.",
        "impact": "Permite que la API o la aplicación web sea cargada dentro de frames o iframes de sitios de terceros no autorizados, haciéndola vulnerable a Clickjacking.",
        "recommendation": "Define frame-ancestors 'none' o 'self' dentro de la cabecera Content-Security-Policy.",
        "code_example": """# Agregar directiva CSP en cabeceras
response.headers["Content-Security-Policy"] = "frame-ancestors 'none';" """,
        "link": "https://owasp.org/www-project-secure-headers/#content-security-policy"
    },
    "security_misconfiguration.http_headers_csp_missing": {
        "title": "Header Content-Security-Policy (CSP) faltante",
        "severity": "high",
        "description": "El header Content-Security-Policy (CSP) no está configurado en las respuestas.",
        "impact": "Los navegadores no tendrán restricciones sobre las fuentes de contenido que pueden cargar, facilitando inyecciones XSS y Clickjacking.",
        "recommendation": "Configura un header CSP restrictivo para el origen de scripts, estilos e imágenes.",
        "code_example": """# Configuración recomendada de CSP básica
response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self';" """,
        "link": "https://owasp.org/www-project-secure-headers/#content-security-policy"
    },
    "security_misconfiguration.http_headers_frame_options_missing": {
        "title": "Header X-Frame-Options faltante",
        "severity": "medium",
        "description": "El header X-Frame-Options no está configurado.",
        "impact": "Permite que las respuestas de la API sean embebidas en frames en páginas web maliciosas, exponiéndolas a ataques de clickjacking.",
        "recommendation": "Configura la cabecera 'X-Frame-Options: DENY' o 'SAMEORIGIN' en tu servidor web o aplicación.",
        "code_example": """# Agregar X-Frame-Options en middleware
response.headers["X-Frame-Options"] = "DENY" """,
        "link": "https://owasp.org/www-project-secure-headers/#x-frame-options"
    },
    "security_misconfiguration.http_headers_hsts_missing": {
        "title": "Header Strict-Transport-Security (HSTS) faltante",
        "severity": "high",
        "description": "El header HSTS no está configurado o no fuerza conexiones seguras.",
        "impact": "Permite que los usuarios accedan a la API a través de conexiones HTTP no cifradas, facilitando ataques de intercepción de tráfico y secuestro de sesión (MITM).",
        "recommendation": "Configura HSTS con un 'max-age' prolongado, incluyendo subdominios y pre-carga si es posible.",
        "code_example": """# Agregar HSTS (forzar HTTPS durante 1 año)
response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload" """,
        "link": "https://owasp.org/www-project-secure-headers/#strict-transport-security"
    },
    "broken_authentication.alg_none": {
        "title": "Algoritmo JWT 'none' permitido",
        "severity": "critical",
        "description": "La API acepta tokens JWT que utilizan el algoritmo de firma 'none' (sin firma).",
        "impact": "Un atacante puede modificar la carga útil del JWT (por ejemplo, cambiar su rol a admin) y enviar el token sin firma para saltarse toda la autenticación.",
        "recommendation": "Configura la biblioteca de validación de JWT para rechazar explícitamente tokens que declaren el algoritmo 'none' en su cabecera.",
        "code_example": """# Validación segura usando PyJWT
import jwt

# Asegura indicar explícitamente los algoritmos permitidos
jwt.decode(token, key, algorithms=["HS256"])""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-alg-none"
    },
    "broken_authentication.blank_secret": {
        "title": "Firma JWT con secreto en blanco (Blank Secret)",
        "severity": "critical",
        "description": "La firma del token JWT es válida cuando se verifica utilizando una clave secreta vacía o en blanco.",
        "impact": "Cualquier persona puede firmar tokens JWT válidos utilizando una clave vacía, obteniendo acceso a cualquier cuenta.",
        "recommendation": "Establece un secreto fuerte de forma segura y valida que la clave utilizada para verificar firmas nunca esté vacía.",
        "code_example": """# Evita usar variables de entorno vacías
import os
SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET no puede estar vacío")""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-blank-secret"
    },
    "broken_authentication.kid_injection": {
        "title": "Inyección en cabecera JWT 'kid'",
        "severity": "critical",
        "description": "La cabecera 'kid' (Key ID) en el token JWT no es validada correctamente, permitiendo inyecciones (como inyecciones SQL o de rutas de archivos).",
        "impact": "Un atacante podría apuntar la clave de verificación a un archivo local bajo su control o inyectar código SQL para evadir la lógica de autenticación.",
        "recommendation": "Sanea y valida rigurosamente el parámetro 'kid' antes de utilizarlo para buscar o cargar la clave de verificación.",
        "code_example": """# Valida que el kid coincida con un patrón seguro o esté en una lista blanca
if not kid.isalnum():
    raise ValueError("Key ID inválido")""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection"
    },
    "broken_authentication.not_verified": {
        "title": "Firma del JWT no es verificada",
        "severity": "critical",
        "description": "La API procesa la carga útil del JWT sin validar si la firma del token es legítima.",
        "impact": "Permite el uso de tokens falsificados y la suplantación completa de identidades.",
        "recommendation": "Asegúrate de verificar siempre la firma del JWT utilizando la clave pública o secreta correspondiente al decodificar.",
        "code_example": """# Asegura verificar la firma
jwt.decode(token, secret_key, verify=True, algorithms=["HS256"])""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-not-verified"
    },
    "broken_authentication.null_signature": {
        "title": "Firma del JWT nula (Null Signature)",
        "severity": "critical",
        "description": "El token JWT es aceptado aunque la sección de la firma esté vacía o ausente.",
        "impact": "Permite la evasión total del control de autenticación mediante la alteración de la cabecera y el cuerpo del token.",
        "recommendation": "Exige la presencia y validez de la firma en cada JWT recibido.",
        "code_example": """# La decodificación estándar en bibliotecas seguras requiere y verifica la firma por defecto. Evita configuraciones inseguras.""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-null-signature"
    },
    "broken_authentication.weak_secret": {
        "title": "Secreto de firma JWT débil",
        "severity": "high",
        "description": "El secreto utilizado para firmar los tokens JWT es corto o predecible (como palabras de diccionario), haciéndolo vulnerable a ataques de fuerza bruta offline.",
        "impact": "Un atacante puede adivinar la clave secreta y firmar tokens arbitrarios para suplantar a cualquier usuario.",
        "recommendation": "Genera claves secretas largas, aleatorias y complejas, y guárdalas de forma segura.",
        "code_example": """# Generar una clave segura en terminal:
# openssl rand -hex 32""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-weak-secret"
    },
    "security_misconfiguration.http_cookies_not_http_only": {
        "title": "Cookies sin atributo HttpOnly",
        "severity": "medium",
        "description": "Se envían cookies sensibles sin la directiva 'HttpOnly'.",
        "impact": "Las cookies pueden ser accedidas mediante scripts del lado del cliente (JavaScript), lo que permite a los atacantes robar identificadores de sesión en ataques XSS.",
        "recommendation": "Establece el flag 'HttpOnly' en todas las cookies de sesión y autenticación.",
        "code_example": """# En FastAPI / Starlette
response.set_cookie(key="session", value="...", httponly=True)""",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"
    },
    "security_misconfiguration.http_cookies_not_secure": {
        "title": "Cookies sin atributo Secure",
        "severity": "high",
        "description": "Se transmiten cookies sensibles sin el flag 'Secure'.",
        "impact": "Las cookies pueden ser enviadas a través de canales HTTP no cifrados, permitiendo su intercepción en redes Wi-Fi inseguras.",
        "recommendation": "Configura la propiedad 'Secure' en todas las cookies para que solo se transmitan vía HTTPS.",
        "code_example": """# Establecer cookie segura
response.set_cookie(key="session", value="...", secure=True)""",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"
    },
    "security_misconfiguration.http_method_allow_override": {
        "title": "Cabecera de sobrescritura de método HTTP permitida",
        "severity": "medium",
        "description": "La API admite cabeceras de sobrescritura de método como X-Http-Method-Override.",
        "impact": "Permite a los atacantes evadir restricciones de nivel de red (como reglas de firewall que bloquean ciertos verbos HTTP como DELETE o PUT).",
        "recommendation": "Desactiva la sobrescritura de métodos HTTP si no es estrictamente necesaria.",
        "code_example": """# Desactiva middleware de sobrescritura de métodos en tu framework (por ejemplo, en Laravel, Express, etc.).""",
        "link": "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/security-misconfiguration/http-method-allow-override"
    },
    "security_misconfiguration.http_trace_method_enabled": {
        "title": "Método HTTP TRACE habilitado",
        "severity": "medium",
        "description": "El método HTTP TRACE está activo en el servidor web de la API.",
        "impact": "Permite ataques de Cross-Site Tracking (XST), donde un atacante puede robar cookies de sesión y credenciales enviadas en las cabeceras HTTP.",
        "recommendation": "Deshabilita el método TRACE en la configuración de tu servidor proxy o servidor web.",
        "code_example": """# En Nginx:
if ($request_method ~ ^(TRACE)$ ) {
    return 405;
}""",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/TRACE"
    },
    "security_misconfiguration.http_track_method_enabled": {
        "title": "Método HTTP TRACK habilitado",
        "severity": "medium",
        "description": "El método HTTP TRACK está habilitado.",
        "impact": "Similar a TRACE, puede exponer información de depuración interna y cabeceras sensibles a atacantes.",
        "recommendation": "Deshabilita el método TRACK en tu servidor web.",
        "code_example": """# En Nginx o IIS deshabilita los verbos no estándar.""",
        "link": "https://techcommunity.microsoft.com/t5/iis-support-blog/http-track-and-trace-verbs/ba-p/784482"
    },
    "security_misconfiguration.tls": {
        "title": "Conexión No Segura (HTTP o TLS obsoleto)",
        "severity": "critical",
        "description": "La API no cifra adecuadamente sus conexiones o admite versiones obsoletas de SSL/TLS.",
        "impact": "Exposición del tráfico de datos en texto claro, permitiendo ataques MITM (Man-in-the-Middle).",
        "recommendation": "Migra a HTTPS, utiliza TLS 1.2 o superior, y deshabilita algoritmos de cifrado débiles.",
        "code_example": """# Forzar TLS 1.3 en Nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;""",
        "link": "https://owasp.org/www-project-secure-headers/#strict-transport-security"
    }
}

class APIScanner:
    """Clase principal que ejecuta todos los escaneos usando VULNAPI"""
    
    def __init__(self, target: str, deep_scan: bool = True, ssl_check: bool = True, scan_type: str = "url", auth_token: str = None):
        self.target = target
        self.deep_scan = deep_scan
        self.ssl_check = ssl_check
        self.scan_type = scan_type
        self.auth_token = auth_token
        self.results = {
            'url': target if scan_type == "url" else "Archivo OpenAPI",
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'secure_count': 0,
            'medium_count': 0,
            'critical_count': 0,
            'score': 'A+',
            'summary': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
        }
        self.progress = 0
        self.status_message = "Iniciando escaneo..."

    def scan_all(self) -> Dict:
        """Ejecuta el escaneo de VULNAPI y mapea los resultados"""
        self.status_message = "Preparando escaneo de VULNAPI..."
        self.progress = 5
        
        # Construir comando
        if self.scan_type == "openapi":
            cmd = ["vulnapi", "scan", "openapi", self.target]
        else:
            cmd = ["vulnapi", "scan", "curl", self.target]
            if not self.ssl_check:
                cmd.append("-k")
        
        # Añadir header de auth si existe
        if self.auth_token:
            cmd.extend(["--header", f"Authorization: Bearer {self.auth_token}"])
            
        # Nombre de archivo de reporte temporal único
        os.makedirs("reports", exist_ok=True)
        temp_report = f"reports/temp_{uuid.uuid4()}.json"
        # Deshabilitar telemetría para acelerar y evitar timeouts
        cmd.append("--sqa-opt-out")
        cmd.extend(["--report-format", "json", "--report-file", temp_report])
        
        try:
            self.status_message = "Ejecutando escáner VULNAPI..."
            self.progress = 15
            
            # Ejecutar subproceso con timeout de 3 minutos
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True,
                timeout=180
            )
            
            # Cargar y parsear resultados del archivo temporal
            if os.path.exists(temp_report):
                try:
                    with open(temp_report, "r", encoding="utf-8") as f:
                        data = json.load(f)
                finally:
                    # Eliminar archivo temporal inmediatamente
                    try:
                        os.remove(temp_report)
                    except Exception:
                        pass
            else:
                raise Exception("El reporte JSON de VULNAPI no se generó. Es posible que la URL o archivo sean inaccesibles.")
                
            # Procesar issues detectados
            issues = []
            for key in ["curl", "graphql", "openapi"]:
                if key in data and isinstance(data[key], dict):
                    issues.extend(data[key].get("issues", []))
                    
            # Filtrar por fallados (vulnerabilidades detectadas)
            failed_issues = [issue for issue in issues if issue.get("status") == "failed"]
            
            vulns = []
            for issue in failed_issues:
                issue_id = issue.get("id", "")
                name = issue.get("name", "")
                url_link = issue.get("url", "")
                cvss_score = issue.get("cvss", {}).get("score", 0.0)
                
                # Clasificar severidad
                severity = "low"
                if cvss_score >= 9.0:
                    severity = "critical"
                elif cvss_score >= 7.0:
                    severity = "high"
                elif cvss_score >= 4.0:
                    severity = "medium"
                elif cvss_score >= 0.1:
                    severity = "low"
                else:
                    # Mapeo personalizado para scores 0.0
                    if any(k in issue_id for k in ["cors_wildcard", "authentication_bypass", "alg_none", "blank_secret", "kid_injection", "null_signature"]):
                        severity = "critical"
                    elif any(k in issue_id for k in ["csp_missing", "hsts_missing", "cookies_not_secure", "weak_secret"]):
                        severity = "high"
                    elif any(k in issue_id for k in ["content_options_missing", "frame_options_missing", "cookies_not_http_only", "trace_method", "track_method"]):
                        severity = "medium"
                    elif any(k in issue_id for k in ["fingerprint", "accept_unauthenticated"]):
                        severity = "info"
                    else:
                        severity = "low"
                        
                # Buscar en el mapa enriquecido en español
                mapped = VULNAPI_ISSUES_MAP.get(issue_id)
                if not mapped:
                    for k, v in VULNAPI_ISSUES_MAP.items():
                        if k in issue_id or issue_id in k:
                            mapped = v
                            break
                            
                if mapped:
                    title = mapped["title"]
                    if severity == "low" and mapped["severity"] != "low":
                        severity = mapped["severity"]
                    description = mapped["description"]
                    impact = mapped["impact"]
                    recommendation = mapped["recommendation"]
                    code_example = mapped["code_example"]
                    link = mapped["link"]
                else:
                    title = name
                    description = f"Vulnerabilidad detectada por VulnAPI: {name}."
                    impact = "Exposición de seguridad identificada en los estándares de OWASP."
                    recommendation = "Valida la configuración del endpoint para seguir las mejores prácticas de seguridad de APIs."
                    code_example = ""
                    link = url_link or "https://owasp.org"
                    
                vulns.append({
                    'title': title,
                    'severity': severity,
                    'detected': True,
                    'description': description,
                    'impact': impact,
                    'recommendation': recommendation,
                    'code_example': code_example,
                    'link': link
                })
                
            # Integrar ActiveFuzzer (SQLi y Rate Limiting) si deep_scan está habilitado y es una URL
            if self.deep_scan and self.scan_type == "url":
                self.status_message = "Ejecutando pruebas activas (Fuzzing y Rate Limit)..."
                self.progress = 80
                try:
                    from backend.active_fuzzer import ActiveFuzzer
                    fuzzer = ActiveFuzzer(self.target)
                    active_vulns = fuzzer.run_all_tests()
                    vulns.extend(active_vulns)
                except Exception as e:
                    print(f"Error al ejecutar fuzzer activo: {e}")

            self.results['vulnerabilities'] = vulns
            
            # Calcular estadísticas de severidades para Trends y UI
            critical = sum(1 for v in vulns if v['severity'] == 'critical')
            high = sum(1 for v in vulns if v['severity'] == 'high')
            medium = sum(1 for v in vulns if v['severity'] == 'medium')
            low = sum(1 for v in vulns if v['severity'] == 'low')
            
            summary = {
                'critical': [v['title'] for v in vulns if v['severity'] == 'critical'],
                'high': [v['title'] for v in vulns if v['severity'] == 'high'],
                'medium': [v['title'] for v in vulns if v['severity'] == 'medium'],
                'low': [v['title'] for v in vulns if v['severity'] == 'low']
            }
            
            self.results['summary'] = summary
            self.results['critical_count'] = critical
            self.results['high_count'] = high
            self.results['medium_count'] = medium
            self.results['secure_count'] = low
            
            # Calcular puntuación global
            total_weight = (critical * 4) + (high * 3) + (medium * 2) + (low * 1)
            if total_weight == 0:
                self.results['score'] = 'A+'
            elif total_weight <= 3:
                self.results['score'] = 'A'
            elif total_weight <= 6:
                self.results['score'] = 'B'
            elif total_weight <= 10:
                self.results['score'] = 'C'
            else:
                self.results['score'] = 'D'
                
            self.progress = 100
            self.status_message = "Escaneo completado"
            
        except Exception as e:
            self.progress = 100
            self.status_message = f"Error en escaneo: {str(e)}"
            # Devolver estructura mínima con error
            self.results['vulnerabilities'] = [{
                'title': 'Error de Ejecución de VulnAPI',
                'severity': 'high',
                'detected': True,
                'description': f'Error al ejecutar vulnapi: {str(e)}',
                'impact': 'No se pudo escanear el endpoint.',
                'recommendation': 'Verifica que la URL sea accesible y que el servicio de VulnAPI esté disponible.',
                'code_example': '',
                'link': ''
            }]
            self.results['critical_count'] = 1
            self.results['high_count'] = 0
            self.results['score'] = 'D'
            
        return self.results

    def get_progress(self) -> Dict:
        """Retorna el estado actual del escaneo"""
        return {
            'progress': self.progress,
            'status': 'completed' if self.progress >= 100 else 'running',
            'message': self.status_message
        }
        
    # Métodos stub para compatibilidad retroactiva
    def scan_cors(self) -> Dict:
        return {}
        
    def scan_security_headers(self) -> List[Dict]:
        return []
        
    def scan_sql_injection(self) -> List[Dict]:
        return []
        
    def scan_rate_limiting(self) -> Dict:
        return {}
        
    def scan_xss(self) -> List[Dict]:
        return []
        
    def scan_ssl(self) -> Dict:
        return {}