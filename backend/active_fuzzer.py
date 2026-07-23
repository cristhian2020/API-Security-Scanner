import requests
import time
import concurrent.futures
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from typing import List, Dict

class ActiveFuzzer:
    """
    Módulo de escaneo activo (Fuzzing) para validar vulnerabilidades 
    que herramientas pasivas como VulnAPI no cubren exhaustivamente (SQLi, Rate Limiting).
    """

    SQLI_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1; DROP TABLE users",
        "1' OR 1=1--",
        "' UNION SELECT NULL, NULL--"
    ]

    SQL_ERRORS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "pg_query()",
        "sqlite3.OperationalError"
    ]

    def __init__(self, url: str):
        self.url = url
        self.headers = {
            "User-Agent": "APIScanner-ActiveFuzzer/1.0"
        }

    def _inject_payload_to_url(self, payload: str) -> str:
        """Inyecta el payload en los parámetros de la URL, o agrega uno genérico si no existen."""
        parsed = urlparse(self.url)
        query_params = parse_qsl(parsed.query)
        
        if not query_params:
            # Si no hay parámetros, probamos agregando un parámetro id genérico
            new_query = urlencode({"id": f"1{payload}", "q": payload})
        else:
            # Si hay parámetros, inyectamos en el primero
            new_params = []
            for k, v in query_params:
                new_params.append((k, f"{v}{payload}"))
            new_query = urlencode(new_params)
            
        return urlunparse(parsed._replace(query=new_query))

    def test_sql_injection(self) -> List[Dict]:
        """
        Prueba inyecciones SQL básicas en parámetros de la URL.
        Retorna una lista de vulnerabilidades encontradas.
        """
        vulns = []
        is_vulnerable = False
        
        for payload in self.SQLI_PAYLOADS:
            test_url = self._inject_payload_to_url(payload)
            try:
                # Timeout corto para evitar colgar el escáner
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                content = response.text.lower()
                
                # Comprobar si hay errores SQL en la respuesta
                for sql_error in self.SQL_ERRORS:
                    if sql_error in content or response.status_code == 500:
                        is_vulnerable = True
                        break
                        
                if is_vulnerable:
                    vulns.append({
                        'title': 'Posible Inyección SQL (SQLi) Detectada',
                        'severity': 'critical',
                        'detected': True,
                        'description': f'Se inyectó el payload "{payload}" y el servidor respondió con un error de base de datos o un código 500.',
                        'impact': 'Un atacante podría leer, modificar o eliminar datos de la base de datos o tomar el control del servidor.',
                        'recommendation': 'Utiliza consultas preparadas (Prepared Statements) o un ORM seguro. Nunca concatenes cadenas para formar consultas SQL.',
                        'code_example': '# En Python (SQLAlchemy):\\nsession.query(User).filter(User.id == user_id).first()\\n\\n# En lugar de:\\n# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                        'link': 'https://owasp.org/www-community/attacks/SQL_Injection'
                    })
                    break # Detener si ya detectó vulnerabilidad
            except requests.exceptions.RequestException:
                pass # Ignorar errores de conexión
                
        return vulns

    def test_rate_limiting(self) -> List[Dict]:
        """
        Realiza una ráfaga de peticiones para verificar si la API implementa Rate Limiting.
        """
        vulns = []
        requests_count = 30 # Ráfaga de 30 peticiones concurrentes
        
        def send_request():
            try:
                return requests.get(self.url, headers=self.headers, timeout=5, verify=False)
            except Exception:
                return None

        status_codes = []
        # Usamos ThreadPoolExecutor para envíos concurrentes rápidos
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_request) for _ in range(requests_count)]
            for future in concurrent.futures.as_completed(futures):
                resp = future.result()
                if resp is not None:
                    status_codes.append(resp.status_code)

        # Si ninguna petición devolvió 429 (Too Many Requests) o 403, es probable que no tenga Rate Limit
        if status_codes and not any(code in [429, 403] for code in status_codes):
            # Para evitar falsos positivos absolutos, validamos que hayan respondido correctamente (200) y no errores (500)
            if any(code == 200 for code in status_codes):
                vulns.append({
                    'title': 'Falta de Límite de Peticiones (Rate Limiting)',
                    'severity': 'high',
                    'detected': True,
                    'description': f'Se enviaron {requests_count} peticiones simultáneas a la API y ninguna fue bloqueada o limitada (HTTP 429).',
                    'impact': 'Permite ataques de Fuerza Bruta, Denegación de Servicio (DoS) y consumo excesivo de recursos de la API.',
                    'recommendation': 'Implementa un mecanismo de Rate Limiting por IP o token de usuario (ej. 100 peticiones por minuto).',
                    'code_example': '# En FastAPI usando slowapi:\\nfrom slowapi import Limiter\\nlimiter = Limiter(key_func=get_remote_address)\\n\\n@app.get("/api")\\n@limiter.limit("5/minute")\\nasync def endpoint():\\n    pass',
                    'link': 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'
                })
        
        return vulns

    def run_all_tests(self) -> List[Dict]:
        """Ejecuta todas las validaciones activas y retorna los resultados."""
        results = []
        # Evitar warnings molestos de SSL
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        results.extend(self.test_sql_injection())
        results.extend(self.test_rate_limiting())
        
        return results
