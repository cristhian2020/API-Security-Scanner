#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Security Scanner - CORS & Headers
Herramienta personalizada para pentesting de APIs
"""

import requests
import json
import sys

def print_banner():
    """Muestra el banner de la herramienta"""
    print("""
    ==========================================
    =    API Security Scanner - v1.0         =
    =    CORS & Headers Analyzer             =
    =    Desarrollado para monografía        =
    ==========================================
    """)

def check_cors(url):
    """Verifica configuraciones de CORS"""
    print(f"[+] Verificando CORS en: {url}")
    
    headers = {
        'Origin': 'https://evil.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        
        cors_header = response.headers.get('Access-Control-Allow-Origin')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
        
        result = {
            'url': url,
            'status_code': response.status_code,
            'cors_header': cors_header,
            'cors_credentials': cors_credentials,
            'vulnerable': False,
            'severity': 'INFO',
            'message': ''
        }
        
        # Análisis de vulnerabilidad
        if cors_header == '*':
            result['vulnerable'] = True
            result['severity'] = 'HIGH'
            result['message'] = 'CRÍTICO: CORS permite cualquier origen (*). Un atacante puede hacer peticiones desde cualquier sitio web.'
            if cors_credentials == 'true':
                result['message'] += ' Además, permite credenciales (cookies) - ¡RIESGO EXTREMO!'
        elif cors_header and cors_header != '*':
            result['vulnerable'] = False
            result['severity'] = 'INFO'
            result['message'] = f'CORS restringido a: {cors_header} - Configuración segura'
        else:
            result['vulnerable'] = False
            result['severity'] = 'INFO'
            result['message'] = 'No se encontró header CORS en la respuesta'
            
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            'url': url,
            'error': f'Error al conectar: {str(e)}',
            'vulnerable': False
        }

def check_security_headers(url):
    """Verifica headers de seguridad comunes"""
    print(f"[+] Verificando headers de seguridad en: {url}")
    
    required_headers = {
        'Content-Security-Policy': 'Previene ataques XSS e inyecciones',
        'Strict-Transport-Security': 'Fuerza conexiones HTTPS',
        'X-Frame-Options': 'Previene clickjacking',
        'X-Content-Type-Options': 'Previene MIME-sniffing',
        'X-XSS-Protection': 'Protección XSS del navegador',
        'Referrer-Policy': 'Controla información de referer'
    }
    
    results = {}
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        
        for header, description in required_headers.items():
            value = response.headers.get(header)
            results[header] = {
                'present': value is not None,
                'value': value if value else 'No presente',
                'description': description,
                'recommendation': ''
            }
            
            # Recomendaciones por header
            if not value:
                if header == 'Content-Security-Policy':
                    results[header]['recommendation'] = 'Agregar: Content-Security-Policy: default-src "self"'
                elif header == 'Strict-Transport-Security':
                    results[header]['recommendation'] = 'Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                elif header == 'X-Frame-Options':
                    results[header]['recommendation'] = 'Agregar: X-Frame-Options: DENY'
                elif header == 'X-Content-Type-Options':
                    results[header]['recommendation'] = 'Agregar: X-Content-Type-Options: nosniff'
                elif header == 'X-XSS-Protection':
                    results[header]['recommendation'] = 'Agregar: X-XSS-Protection: 1; mode=block'
                elif header == 'Referrer-Policy':
                    results[header]['recommendation'] = 'Agregar: Referrer-Policy: strict-origin-when-cross-origin'
        
        # Verificar información del servidor (leak)
        server_header = response.headers.get('Server')
        if server_header:
            results['server_info'] = {
                'present': True,
                'value': server_header,
                'description': 'Información del servidor expuesta',
                'recommendation': 'Ocultar versión del servidor o usar un nombre genérico'
            }
        
        return results
        
    except requests.exceptions.RequestException as e:
        return {
            'error': f'Error al conectar: {str(e)}'
        }

def generate_report(cors_result, headers_result):
    """Genera un reporte formateado"""
    print("\n" + "="*60)
    print("    REPORTE DE SEGURIDAD DE API")
    print("="*60)
    
    # Resumen CORS
    print("\n[1] ANÁLISIS DE CORS")
    print("-"*40)
    if cors_result.get('error'):
        print(f"✗ Error: {cors_result['error']}")
    else:
        status = "✓" if not cors_result['vulnerable'] else "✗"
        print(f"URL: {cors_result['url']}")
        print(f"Status Code: {cors_result['status_code']}")
        print(f"Access-Control-Allow-Origin: {cors_result['cors_header']}")
        print(f"Access-Control-Allow-Credentials: {cors_result['cors_credentials']}")
        print(f"\n{status} Estado: {cors_result['message']}")
        
        if cors_result['vulnerable']:
            print("\n[!] RECOMENDACIÓN: Implementar lista blanca de orígenes")
    
    # Análisis de Headers
    print("\n[2] ANÁLISIS DE HEADERS DE SEGURIDAD")
    print("-"*40)
    
    if headers_result.get('error'):
        print(f"✗ Error: {headers_result['error']}")
    else:
        for header, info in headers_result.items():
            if header != 'server_info':
                status = "✓" if info['present'] else "✗"
                print(f"\n{status} {header}")
                print(f"   Valor: {info['value']}")
                print(f"   Descripción: {info['description']}")
                if info['recommendation']:
                    print(f"   [i] Recomendación: {info['recommendation']}")
        
        # Información del servidor
        if 'server_info' in headers_result:
            print(f"\n⚠ SERVER LEAK: {headers_result['server_info']['value']}")
            print(f"   Recomendación: {headers_result['server_info']['recommendation']}")
    
    print("\n" + "="*60)
    print("    FIN DEL REPORTE")
    print("="*60)

def main():
    print_banner()
    
    # Obtener URL del usuario
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Ingresa la URL de la API a escanear (ej: https://httpbin.org/post): ").strip()
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    print(f"\n[+] Escaneando: {url}")
    print("-"*50)
    
    # Ejecutar escaneos
    cors_result = check_cors(url)
    headers_result = check_security_headers(url)
    
    # Generar reporte
    generate_report(cors_result, headers_result)

if __name__ == "__main__":
    main()