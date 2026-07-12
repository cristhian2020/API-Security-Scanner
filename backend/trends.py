# backend/trends.py
"""
Dashboard de Tendencias y Estadísticas
Análisis de vulnerabilidades a lo largo del tiempo
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import statistics
from collections import Counter

class TrendsDashboard:
    """Clase para análisis de tendencias de escaneos"""
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        self.scans_data = []
        self._load_all_scans()
    
    def _load_all_scans(self):
        """Carga todos los reportes guardados"""
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir, exist_ok=True)
            return
        
        for filename in os.listdir(self.reports_dir):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(self.reports_dir, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Extraer metadatos del archivo
                        scan_id = filename.replace('.json', '')
                        data['scan_id'] = scan_id
                        # Usar timestamp del reporte o fecha de creación
                        if 'timestamp' in data:
                            data['date'] = data['timestamp']
                        else:
                            data['date'] = datetime.fromtimestamp(
                                os.path.getctime(filepath)
                            ).isoformat()
                        self.scans_data.append(data)
                except Exception as e:
                    print(f"Error cargando {filename}: {e}")
        
        # Ordenar por fecha (más reciente primero)
        self.scans_data.sort(key=lambda x: x.get('date', ''), reverse=True)
    
    # ============================================================
    # ESTADÍSTICAS GENERALES
    # ============================================================
    def get_summary_stats(self) -> Dict:
        """Obtiene estadísticas generales de todos los escaneos"""
        if not self.scans_data:
            return {
                'total_scans': 0,
                'avg_score': 'N/A',
                'total_critical': 0,
                'total_high': 0,
                'total_medium': 0,
                'total_low': 0,
                'total_vulnerabilities': 0,
                'best_score': 'N/A',
                'worst_score': 'N/A',
                'unique_urls': 0
            }
        
        total = len(self.scans_data)
        
        # Calcular promedio de puntuaciones
        score_map = {'A+': 100, 'A': 90, 'B': 75, 'C': 60, 'D': 40}
        scores = [score_map.get(s.get('score', 'D'), 40) for s in self.scans_data]
        avg_score = statistics.mean(scores) if scores else 0
        
        # Convertir promedio a letra
        if avg_score >= 95:
            avg_letter = 'A+'
        elif avg_score >= 85:
            avg_letter = 'A'
        elif avg_score >= 70:
            avg_letter = 'B'
        elif avg_score >= 55:
            avg_letter = 'C'
        else:
            avg_letter = 'D'
        
        # Mejor y peor puntuación
        best = max(scores) if scores else 0
        worst = min(scores) if scores else 0
        best_letter = 'A+' if best >= 95 else 'A' if best >= 85 else 'B' if best >= 70 else 'C' if best >= 55 else 'D'
        worst_letter = 'A+' if worst >= 95 else 'A' if worst >= 85 else 'B' if worst >= 70 else 'C' if worst >= 55 else 'D'
        
        # URLs únicas
        unique_urls = len(set(s.get('url', '') for s in self.scans_data))
        
        return {
            'total_scans': total,
            'avg_score': avg_letter,
            'total_critical': sum(s.get('critical_count', 0) for s in self.scans_data),
            'total_high': sum(s.get('high_count', 0) for s in self.scans_data),
            'total_medium': sum(s.get('medium_count', 0) for s in self.scans_data),
            'total_low': sum(s.get('secure_count', 0) for s in self.scans_data),
            'total_vulnerabilities': sum(len(s.get('vulnerabilities', [])) for s in self.scans_data),
            'best_score': best_letter,
            'worst_score': worst_letter,
            'unique_urls': unique_urls
        }
    
    # ============================================================
    # TENDENCIA POR SEVERIDAD
    # ============================================================
    def get_trend_by_severity(self, days: int = 30) -> Dict:
        """
        Obtiene tendencia de vulnerabilidades por severidad
        Args:
            days: Número de días a analizar (default: 30)
        Returns:
            Diccionario con fechas y conteos por severidad
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        trend = {
            'dates': [],
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total': []
        }
        
        # Filtrar por fecha
        recent_scans = []
        for scan in self.scans_data:
            try:
                scan_date = datetime.fromisoformat(scan.get('date', '').replace('Z', '+00:00'))
                if scan_date >= cutoff_date:
                    recent_scans.append(scan)
            except:
                # Si no se puede parsear, incluir igual
                recent_scans.append(scan)
        
        # Ordenar por fecha ascendente para la tendencia
        recent_scans.sort(key=lambda x: x.get('date', ''))
        
        for scan in recent_scans:
            # Extraer recuento por severidad
            critical = scan.get('critical_count', 0)
            high = len(scan.get('summary', {}).get('high', []))
            medium = scan.get('medium_count', 0)
            low = scan.get('secure_count', 0)
            
            date_str = scan.get('date', '')[:10]
            trend['dates'].append(date_str)
            trend['critical'].append(critical)
            trend['high'].append(high)
            trend['medium'].append(medium)
            trend['low'].append(low)
            trend['total'].append(critical + high + medium + low)
        
        return trend
    
    # ============================================================
    # VULNERABILIDADES MÁS FRECUENTES
    # ============================================================
    def get_frequent_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """
        Obtiene las vulnerabilidades más frecuentes
        Args:
            limit: Número máximo de resultados (default: 10)
        Returns:
            Lista de vulnerabilidades con su frecuencia
        """
        vuln_counter = {}
        
        for scan in self.scans_data:
            for vuln in scan.get('vulnerabilities', []):
                title = vuln.get('title', 'Desconocida')
                severity = vuln.get('severity', 'info')
                key = f"{title}|{severity}"
                
                if key not in vuln_counter:
                    vuln_counter[key] = {
                        'title': title,
                        'severity': severity,
                        'count': 0,
                        'description': vuln.get('description', ''),
                        'recommendation': vuln.get('recommendation', ''),
                        'link': vuln.get('link', '')
                    }
                vuln_counter[key]['count'] += 1
        
        # Ordenar por frecuencia (más frecuentes primero)
        sorted_vulns = sorted(vuln_counter.values(), key=lambda x: x['count'], reverse=True)
        
        return sorted_vulns[:limit]
    
    # ============================================================
    # EVOLUCIÓN DE PUNTUACIÓN
    # ============================================================
    def get_score_evolution(self, days: int = 30) -> Dict:
        """
        Obtiene la evolución de la puntuación en el tiempo
        Args:
            days: Número de días a analizar (default: 30)
        Returns:
            Diccionario con fechas y puntuaciones
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        score_map = {'A+': 100, 'A': 90, 'B': 75, 'C': 60, 'D': 40}
        
        evolution = {
            'dates': [],
            'scores': [],
            'score_labels': []
        }
        
        # Filtrar y ordenar
        recent_scans = []
        for scan in self.scans_data:
            try:
                scan_date = datetime.fromisoformat(scan.get('date', '').replace('Z', '+00:00'))
                if scan_date >= cutoff_date:
                    recent_scans.append(scan)
            except:
                recent_scans.append(scan)
        
        recent_scans.sort(key=lambda x: x.get('date', ''))
        
        for scan in recent_scans:
            score = scan.get('score', 'D')
            date_str = scan.get('date', '')[:10]
            evolution['dates'].append(date_str)
            evolution['scores'].append(score_map.get(score, 40))
            evolution['score_labels'].append(score)
        
        return evolution
    
    # ============================================================
    # DISTRIBUCIÓN DE VULNERABILIDADES
    # ============================================================
    def get_vulnerability_distribution(self) -> Dict:
        """
        Obtiene la distribución de vulnerabilidades por severidad
        Returns:
            Diccionario con conteos por severidad
        """
        distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for scan in self.scans_data:
            for vuln in scan.get('vulnerabilities', []):
                severity = vuln.get('severity', 'info')
                if severity in distribution:
                    distribution[severity] += 1
                else:
                    distribution['info'] += 1
        
        return distribution
    
    # ============================================================
    # ANÁLISIS POR URL
    # ============================================================
    def get_url_analysis(self) -> List[Dict]:
        """
        Agrupa escaneos por URL y calcula estadísticas por sitio
        Returns:
            Lista de análisis por URL
        """
        url_groups = {}
        
        for scan in self.scans_data:
            url = scan.get('url', '')
            if url not in url_groups:
                url_groups[url] = {
                    'url': url,
                    'scans': [],
                    'last_scan': None,
                    'best_score': 'D',
                    'worst_score': 'A+',
                    'avg_score': 0,
                    'total_critical': 0,
                    'total_medium': 0
                }
            
            url_groups[url]['scans'].append(scan)
            
            # Actualizar estadísticas
            score_map = {'A+': 100, 'A': 90, 'B': 75, 'C': 60, 'D': 40}
            scores = [score_map.get(s.get('score', 'D'), 40) for s in url_groups[url]['scans']]
            avg = statistics.mean(scores) if scores else 0
            url_groups[url]['avg_score'] = avg
            
            # Mejor y peor
            best = max(scores) if scores else 0
            worst = min(scores) if scores else 0
            best_letter = 'A+' if best >= 95 else 'A' if best >= 85 else 'B' if best >= 70 else 'C' if best >= 55 else 'D'
            worst_letter = 'A+' if worst >= 95 else 'A' if worst >= 85 else 'B' if worst >= 70 else 'C' if worst >= 55 else 'D'
            url_groups[url]['best_score'] = best_letter
            url_groups[url]['worst_score'] = worst_letter
            
            url_groups[url]['total_critical'] = sum(s.get('critical_count', 0) for s in url_groups[url]['scans'])
            url_groups[url]['total_medium'] = sum(s.get('medium_count', 0) for s in url_groups[url]['scans'])
            
            # Último escaneo
            latest = max(url_groups[url]['scans'], key=lambda x: x.get('date', ''))
            url_groups[url]['last_scan'] = latest.get('date', '')
            url_groups[url]['last_score'] = latest.get('score', 'D')
        
        return list(url_groups.values())
    
    # ============================================================
    # ESTADÍSTICAS DIARIAS
    # ============================================================
    def get_daily_stats(self, days: int = 7) -> Dict:
        """
        Obtiene estadísticas diarias de escaneos
        Args:
            days: Número de días a analizar (default: 7)
        Returns:
            Diccionario con estadísticas por día
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        daily_stats = {}
        
        for scan in self.scans_data:
            try:
                scan_date = datetime.fromisoformat(scan.get('date', '').replace('Z', '+00:00'))
                if scan_date >= cutoff_date:
                    date_key = scan_date.strftime('%Y-%m-%d')
                    
                    if date_key not in daily_stats:
                        daily_stats[date_key] = {
                            'date': date_key,
                            'scans': 0,
                            'critical': 0,
                            'medium': 0,
                            'scores': []
                        }
                    
                    daily_stats[date_key]['scans'] += 1
                    daily_stats[date_key]['critical'] += scan.get('critical_count', 0)
                    daily_stats[date_key]['medium'] += scan.get('medium_count', 0)
                    
                    score_map = {'A+': 100, 'A': 90, 'B': 75, 'C': 60, 'D': 40}
                    daily_stats[date_key]['scores'].append(score_map.get(scan.get('score', 'D'), 40))
            except:
                pass
        
        # Calcular promedio de puntuación por día
        for date_key, stats in daily_stats.items():
            if stats['scores']:
                avg = statistics.mean(stats['scores'])
                if avg >= 95:
                    stats['avg_score'] = 'A+'
                elif avg >= 85:
                    stats['avg_score'] = 'A'
                elif avg >= 70:
                    stats['avg_score'] = 'B'
                elif avg >= 55:
                    stats['avg_score'] = 'C'
                else:
                    stats['avg_score'] = 'D'
            else:
                stats['avg_score'] = 'N/A'
        
        return daily_stats
    
    # ============================================================
    # GENERAR DASHBOARD COMPLETO
    # ============================================================
    def get_full_dashboard(self, days: int = 30) -> Dict:
        """
        Genera un dashboard completo con todas las estadísticas
        Args:
            days: Número de días para análisis de tendencia (default: 30)
        Returns:
            Diccionario con todas las métricas del dashboard
        """
        return {
            'summary': self.get_summary_stats(),
            'trends': self.get_trend_by_severity(days),
            'score_evolution': self.get_score_evolution(days),
            'frequent_vulnerabilities': self.get_frequent_vulnerabilities(10),
            'distribution': self.get_vulnerability_distribution(),
            'url_analysis': self.get_url_analysis(),
            'daily_stats': self.get_daily_stats(7),
            'total_scans': len(self.scans_data)
        }
    
    # ============================================================
    # EXPORTAR DATOS
    # ============================================================
    def export_to_json(self, filepath: str = "dashboard_data.json") -> bool:
        """
        Exporta todos los datos del dashboard a un archivo JSON
        Args:
            filepath: Ruta del archivo de salida
        Returns:
            True si se exportó correctamente
        """
        try:
            data = self.get_full_dashboard()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exportando: {e}")
            return False


# ============================================================
# EJEMPLO DE USO Y PRUEBA
# ============================================================
if __name__ == "__main__":
    # Crear instancia del dashboard
    dashboard = TrendsDashboard("reports")
    
    # Mostrar estadísticas generales
    print("=" * 60)
    print("  📊 DASHBOARD DE TENDENCIAS - API SECURITY SCANNER")
    print("=" * 60)
    
    summary = dashboard.get_summary_stats()
    print(f"\n📈 RESUMEN GENERAL:")
    print(f"   Total de escaneos: {summary['total_scans']}")
    print(f"   URLs únicas: {summary['unique_urls']}")
    print(f"   Puntuación promedio: {summary['avg_score']}")
    print(f"   Mejor puntuación: {summary['best_score']}")
    print(f"   Peor puntuación: {summary['worst_score']}")
    print(f"   Vulnerabilidades totales: {summary['total_vulnerabilities']}")
    
    # Vulnerabilidades más frecuentes
    print(f"\n🔍 VULNERABILIDADES MÁS FRECUENTES:")
    frequent = dashboard.get_frequent_vulnerabilities(5)
    for i, vuln in enumerate(frequent, 1):
        print(f"   {i}. {vuln['title']} ({vuln['severity']}) - {vuln['count']} veces")
    
    # Distribución
    print(f"\n📊 DISTRIBUCIÓN POR SEVERIDAD:")
    dist = dashboard.get_vulnerability_distribution()
    for severity, count in dist.items():
        if count > 0:
            emoji = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵" if severity == "low" else "⚪"
            print(f"   {emoji} {severity.upper()}: {count}")
    
    # Exportar dashboard completo
    dashboard.export_to_json("dashboard_export.json")
    print(f"\n✅ Dashboard exportado a: dashboard_export.json")
    
    print("\n" + "=" * 60)