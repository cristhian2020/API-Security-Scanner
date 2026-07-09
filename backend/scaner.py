# backend/scanner.py
"""
API Security Scanner - Módulo de Escaneo
Base para la aplicación web y CLI
"""

import requests
import json
import time
import urllib.parse
from typing import Dict, List, Optional
from datetime import datetime

class APIScanner:
    """Clase principal que ejecuta todos los escaneos"""
    
    def __init__(self, url: str, deep_scan: bool = True, ssl_check: bool = True):
        self.url = url
        self.deep_scan = deep_scan
        self.ssl_check = ssl_check
        self.results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'secure_count': 0,
            'medium_count': 0,
            'critical_count': 0,
            'score': 'A+',
            'summary': []
        }
        self.progress = 0
        self.status_message = "Iniciando escaneo..."
    
    def scan_cors(self) -> Dict:
        """Verifica configuraciones de CORS"""
        self.status_message = "Verificando CORS..."
        self.progress = 10
        
        headers = {
            'Origin': 'https://evil.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        
        try:
            response = requests.get(self.url, headers=headers, timeout=10, allow_redirects=False)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin')
            cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
            
            if cors_header == '*':
                result = {
                    'title': 'CORS permite cualquier origen (*)',
                    'severity': 'critical',
                    'detected': True,
                    'description': 'CORS está configurado con "*" permitiendo que cualquier sitio web acceda a tu API.',
                    'impact': 'Un atacante puede crear un sitio malicioso que haga peticiones a tu API usando las credenciales del usuario.',
                    'recommendation': 'Restringe CORS a dominios específicos y autorizados.',
                    'code_example': '''# Python/Flask - Configuración segura de CORS
ALLOWED_ORIGINS = ['https://tudominio.com', 'https://app.tudominio.com']

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response''',
                    'link': 'https://owasp.org/www-project-secure-headers/#cross-origin-resource-sharing'
                }
                if cors_credentials == 'true':
                    result['description'] += ' Además, permite credenciales (cookies) - ¡RIESGO EXTREMO!'
                return result
            elif cors_header:
                return {
                    'title': 'CORS: Configuración segura',
                    'severity': 'info',
                    'detected': False,
                    'description': f'CORS restringido a: {cors_header}',
                    'impact': '',
                    'recommendation': '',
                    'code_example': '',
                    'link': ''
                }
            else:
                return {
                    'title': 'CORS: No configurado',
                    'severity': 'info',
                    'detected': False,
                    'description': 'No se encontró el header Access-Control-Allow-Origin',
                    'impact': '',
                    'recommendation': '',
                    'code_example': '',
                    'link': ''
                }
        except Exception as e:
            return {
                'title': 'Error en escaneo CORS',
                'severity': 'info',
                'detected': False,
                'description': f'Error: {str(e)}',
                'impact': '',
                'recommendation': '',
                'code_example': '',
                'link': ''
            }
    
    def scan_security_headers(self) -> List[Dict]:
        """Verifica headers de seguridad"""
        self.status_message = "Verificando headers de seguridad..."
        self.progress = 30
        
        security_headers = {
            'Content-Security-Policy': {
                'title': 'Content-Security-Policy (CSP) faltante',
                'severity': 'critical',
                'description': 'El header CSP no está configurado.',
                'impact': 'Permite ataques XSS e inyecciones de scripts maliciosos.',
                'recommendation': 'Agrega el header Content-Security-Policy para restringir fuentes de contenido.',
                'code_example': '''# Python/Flask - Configuración de CSP
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:;"
    )
    return response''',
                'link': 'https://owasp.org/www-project-secure-headers/#content-security-policy'
            },
            'Strict-Transport-Security': {
                'title': 'Strict-Transport-Security (HSTS) faltante',
                'severity': 'high',
                'description': 'El header HSTS no está configurado.',
                'impact': 'Permite ataques Man-in-the-Middle al no forzar conexiones HTTPS.',
                'recommendation': 'Configura HSTS para forzar conexiones HTTPS por un período prolongado.',
                'code_example': '''# Python/Flask - Configuración de HSTS
@app.after_request
def add_hsts(response):
    response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"
    return response''',
                'link': 'https://owasp.org/www-project-secure-headers/#strict-transport-security'
            },
            'X-Frame-Options': {
                'title': 'X-Frame-Options faltante',
                'severity': 'medium',
                'description': 'El header X-Frame-Options no está configurado.',
                'impact': 'Permite que tu página sea embebida en iframes (riesgo de clickjacking).',
                'recommendation': 'Agrega X-Frame-Options: DENY o SAMEORIGIN.',
                'code_example': '''# Python/Flask - Configuración de X-Frame-Options
@app.after_request
def add_frame_options(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response''',
                'link': 'https://owasp.org/www-project-secure-headers/#x-frame-options'
            },
            'X-Content-Type-Options': {
                'title': 'X-Content-Type-Options faltante',
                'severity': 'medium',
                'description': 'El header X-Content-Type-Options no está configurado.',
                'impact': 'Podría permitir MIME-sniffing y ejecución de scripts maliciosos.',
                'recommendation': 'Agrega X-Content-Type-Options: nosniff.',
                'code_example': '''# Python/Flask - Configuración de X-Content-Type-Options
@app.after_request
def add_content_type_options(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response''',
                'link': 'https://owasp.org/www-project-secure-headers/#x-content-type-options'
            },
            'X-XSS-Protection': {
                'title': 'X-XSS-Protection faltante',
                'severity': 'low',
                'description': 'El header X-XSS-Protection no está configurado.',
                'impact': 'Menor protección contra ataques XSS en navegadores antiguos.',
                'recommendation': 'Agrega X-XSS-Protection: 1; mode=block.',
                'code_example': '''# Python/Flask - Configuración de X-XSS-Protection
@app.after_request
def add_xss_protection(response):
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response''',
                'link': 'https://owasp.org/www-project-secure-headers/#x-xss-protection'
            },
            'Referrer-Policy': {
                'title': 'Referrer-Policy faltante',
                'severity': 'low',
                'description': 'El header Referrer-Policy no está configurado.',
                'impact': 'Puede filtrar información sensible en las URLs de referencia.',
                'recommendation': 'Agrega Referrer-Policy: strict-origin-when-cross-origin.',
                'code_example': '''# Python/Flask - Configuración de Referrer-Policy
@app.after_request
def add_referrer_policy(response):
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response''',
                'link': 'https://owasp.org/www-project-secure-headers/#referrer-policy'
            }
        }
        
        results = []
        
        try:
            response = requests.get(self.url, timeout=10, allow_redirects=False)
            
            for header, info in security_headers.items():
                if header not in response.headers:
                    vuln = info.copy()
                    vuln['detected'] = True
                    results.append(vuln)
                else:
                    results.append({
                        'title': f'{header}: Configurado correctamente',
                        'severity': 'info',
                        'detected': False,
                        'description': f'Header {header} presente: {response.headers[header]}',
                        'impact': '',
                        'recommendation': '',
                        'code_example': '',
                        'link': ''
                    })
            
            # Verificar información del servidor
            server_header = response.headers.get('Server')
            if server_header and 'LiteSpeed' in server_header:
                results.append({
                    'title': 'Exposición de información del servidor',
                    'severity': 'low',
                    'detected': True,
                    'description': f'El servidor revela su identidad: {server_header}',
                    'impact': 'Un atacante puede buscar vulnerabilidades específicas para esta versión de servidor.',
                    'recommendation': 'Oculta la versión del servidor o usa un nombre genérico en producción.',
                    'code_example': '''# Nginx - Ocultar versión
server_tokens off;

# Apache - Ocultar versión
ServerTokens Prod
ServerSignature Off''',
                    'link': 'https://owasp.org/www-project-secure-headers/#server'
                })
            
        except Exception as e:
            results.append({
                'title': 'Error en escaneo de headers',
                'severity': 'info',
                'detected': False,
                'description': f'Error: {str(e)}',
                'impact': '',
                'recommendation': '',
                'code_example': '',
                'link': ''
            })
        
        return results
    
    def scan_xss(self) -> List[Dict]:
        """Prueba básica de XSS"""
        if not self.deep_scan:
            return []
        
        self.status_message = "Probando vulnerabilidades XSS..."
        self.progress = 60
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "'';!--\"<XSS>=&{()}"
        ]
        
        results = []
        
        try:
            for payload in xss_payloads:
                test_url = f"{self.url}?test={urllib.parse.quote(payload)}"
                response = requests.get(test_url, timeout=10, allow_redirects=False)
                
                if payload in response.text:
                    results.append({
                        'title': 'Posible XSS Reflejado',
                        'severity': 'high',
                        'detected': True,
                        'description': f'El payload se refleja en la respuesta: {payload[:30]}...',
                        'impact': 'Un atacante puede ejecutar scripts maliciosos en el navegador de los usuarios.',
                        'recommendation': 'Valida y escapa toda entrada de usuario. Implementa CSP.',
                        'code_example': '''# Python/Flask - Escapado seguro de entrada
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"Resultados para: {escape(query)}"''',
                        'link': 'https://owasp.org/www-community/attacks/xss/'
                    })
                    break
            
            if not results:
                results.append({
                    'title': 'XSS: No se detectaron vulnerabilidades',
                    'severity': 'info',
                    'detected': False,
                    'description': 'No se encontraron XSS reflejados con los payloads probados',
                    'impact': '',
                    'recommendation': '',
                    'code_example': '',
                    'link': ''
                })
                
        except Exception as e:
            results.append({
                'title': 'Error en prueba XSS',
                'severity': 'info',
                'detected': False,
                'description': f'Error: {str(e)}',
                'impact': '',
                'recommendation': '',
                'code_example': '',
                'link': ''
            })
        
        return results
    
    def scan_ssl(self) -> Dict:
        """Verifica SSL/TLS"""
        if not self.ssl_check:
            return {'detected': False, 'description': 'SSL Check desactivado'}
        
        self.status_message = "Verificando SSL/TLS..."
        self.progress = 80
        
        if not self.url.startswith('https://'):
            return {
                'title': 'Conexión No Segura (HTTP)',
                'severity': 'critical',
                'detected': True,
                'description': 'La API usa HTTP en lugar de HTTPS.',
                'impact': 'Todos los datos viajan en texto plano, permitiendo ataques MITM.',
                'recommendation': 'Migra a HTTPS y configura HSTS para forzar conexiones seguras.',
                'code_example': '''# Nginx - Configuración SSL y redirección
server {
    listen 443 ssl http2;
    server_name tudominio.com;
    
    ssl_certificate /etc/letsencrypt/live/tudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tudominio.com/privkey.pem;
}

# Redirigir HTTP a HTTPS
server {
    listen 80;
    server_name tudominio.com;
    return 301 https://$server_name$request_uri;
}''',
                'link': 'https://owasp.org/www-project-secure-headers/#strict-transport-security'
            }
        else:
            return {
                'title': 'SSL/TLS: Conexión Segura',
                'severity': 'info',
                'detected': False,
                'description': 'La API usa HTTPS correctamente',
                'impact': '',
                'recommendation': '',
                'code_example': '',
                'link': ''
            }
    
    def scan_all(self) -> Dict:
        """Ejecuta todos los escaneos y compila resultados"""
        self.status_message = "Iniciando escaneo completo..."
        self.progress = 5
        
        results = []
        
        # 1. CORS
        cors_result = self.scan_cors()
        if cors_result.get('detected', False):
            results.append(cors_result)
        
        # 2. Headers de seguridad
        header_results = self.scan_security_headers()
        for result in header_results:
            if result.get('detected', False):
                results.append(result)
        
        # 3. XSS (si está activado)
        xss_results = self.scan_xss()
        for result in xss_results:
            if result.get('detected', False):
                results.append(result)
        
        # 4. SSL
        ssl_result = self.scan_ssl()
        if ssl_result.get('detected', False):
            results.append(ssl_result)
        
        # 5. Calcular estadísticas
        self.results['vulnerabilities'] = results
        
        critical = sum(1 for v in results if v.get('severity') == 'critical')
        high = sum(1 for v in results if v.get('severity') == 'high')
        medium = sum(1 for v in results if v.get('severity') == 'medium')
        low = sum(1 for v in results if v.get('severity') == 'low')
        
        # Clasificar vulnerabilidades por severidad para el resumen
        summary = {
            'critical': [v['title'] for v in results if v.get('severity') == 'critical'],
            'high': [v['title'] for v in results if v.get('severity') == 'high'],
            'medium': [v['title'] for v in results if v.get('severity') == 'medium'],
            'low': [v['title'] for v in results if v.get('severity') == 'low']
        }
        
        self.results['summary'] = summary
        self.results['critical_count'] = critical + high
        self.results['medium_count'] = medium
        self.results['secure_count'] = low
        
        # Calcular score
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
        
        return self.results
    
    def get_progress(self) -> Dict:
        """Retorna el estado actual del escaneo"""
        return {
            'progress': self.progress,
            'status': 'completed' if self.progress >= 100 else 'running',
            'message': self.status_message
        }