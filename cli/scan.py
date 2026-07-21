#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Security Scanner - Interfaz CLI
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scaner import APIScanner
import json
import argparse

def main():
    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(
        description="API Security Scanner - Herramienta de línea de comandos",
        epilog="Ejemplo: python scan.py https://api.ejemplo.com --json"
    )
    parser.add_argument("url", help="URL de la API a escanear")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    parser.add_argument("--output", "-o", help="Archivo para guardar el reporte")
    parser.add_argument("--no-deep", action="store_true", help="Desactivar escaneo profundo")
    parser.add_argument("--no-ssl", action="store_true", help="Desactivar verificación SSL")
    
    args = parser.parse_args()
    
    scanner = APIScanner(
        args.url,
        deep_scan=not args.no_deep,
        ssl_check=not args.no_ssl
    )
    
    results = scanner.scan_all()
    
    if args.json:
        output = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"✅ Reporte guardado en: {args.output}")
        else:
            print(output)
    else:
        # Salida formateada
        print("\n" + "="*70)
        print("    API SECURITY SCANNER - REPORTE DE SEGURIDAD")
        print("="*70)
        print(f"📍 URL: {results['url']}")
        print(f"📊 Puntuación: {results['score']}")
        print(f"🔴 Críticas: {results['critical_count']}")
        print(f"🟡 Medias: {results['medium_count']}")
        print(f"🟢 Bjas: {results['secure_count']}")
        print("-"*70)
        print("📋 DETALLE DE VULNERABILIDADES:")
        print("-"*70)
        
        if results['vulnerabilities']:
            for v in results['vulnerabilities']:
                severity = v.get('severity', 'info').upper()
                print(f"\n[{severity}] {v['title']}")
                print(f"   📝 {v['description']}")
                if v.get('recommendation'):
                    print(f"   💡 {v['recommendation']}")
        else:
            print("   🎉 ¡No se encontraron vulnerabilidades!")
        
        print("\n" + "="*70)

if __name__ == "__main__":
    main()