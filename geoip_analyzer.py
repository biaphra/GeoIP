#!/usr/bin/env python3
"""
GeoIP Analyzer - Sistema de Geolocalização de IP
Desenvolvido por Biaphra Araujo
"""

import requests
import json
import ipaddress
import validators
from typing import Dict, List, Optional, Union
from datetime import datetime
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import sys

console = Console()

class GeoIPAnalyzer:
    """Classe principal para análise de geolocalização de IP"""
    
    def __init__(self):
        self.apis = {
            'hackertarget': {
                'url': 'https://api.hackertarget.com/geoip/?q={}',
                'method': 'GET',
                'format': 'text'
            },
            'ipapi': {
                'url': 'http://ip-api.com/json/{}',
                'method': 'GET',
                'format': 'json'
            },
            'ipinfo': {
                'url': 'https://ipinfo.io/{}/json',
                'method': 'GET',
                'format': 'json'
            },
            'freegeoip': {
                'url': 'https://freegeoip.app/json/{}',
                'method': 'GET',
                'format': 'json'
            }
        }
        self.history = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GeoIP-Analyzer/1.0 (Security Analysis Tool)'
        })
    
    def validate_ip(self, ip: str) -> bool:
        """Valida se o endereço IP é válido (IPv4 ou IPv6)"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_private_ip(self, ip: str) -> bool:
        """Verifica se o IP é privado"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def query_hackertarget(self, ip: str) -> Dict:
        """Consulta a API HackerTarget"""
        try:
            url = self.apis['hackertarget']['url'].format(ip)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                data = {}
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        data[key.strip()] = value.strip()
                
                return {
                    'success': True,
                    'source': 'HackerTarget',
                    'ip': ip,
                    'country': data.get('Country', 'N/A'),
                    'country_code': data.get('Country Code', 'N/A'),
                    'region': data.get('State', 'N/A'),
                    'city': data.get('City', 'N/A'),
                    'latitude': data.get('Latitude', 'N/A'),
                    'longitude': data.get('Longitude', 'N/A'),
                    'isp': data.get('ISP', 'N/A'),
                    'organization': data.get('Organization', 'N/A'),
                    'timezone': data.get('Timezone', 'N/A'),
                    'raw_data': data
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def query_ipapi(self, ip: str) -> Dict:
        """Consulta a API IP-API"""
        try:
            url = self.apis['ipapi']['url'].format(ip)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'source': 'IP-API',
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'latitude': str(data.get('lat', 'N/A')),
                        'longitude': str(data.get('lon', 'N/A')),
                        'isp': data.get('isp', 'N/A'),
                        'organization': data.get('org', 'N/A'),
                        'timezone': data.get('timezone', 'N/A'),
                        'zip_code': data.get('zip', 'N/A'),
                        'as_number': data.get('as', 'N/A'),
                        'raw_data': data
                    }
                else:
                    return {'success': False, 'error': data.get('message', 'Unknown error')}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def query_ipinfo(self, ip: str) -> Dict:
        """Consulta a API IPInfo"""
        try:
            url = self.apis['ipinfo']['url'].format(ip)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'bogon' not in data:
                    loc = data.get('loc', ',').split(',')
                    latitude = loc[0] if len(loc) > 0 else 'N/A'
                    longitude = loc[1] if len(loc) > 1 else 'N/A'
                    
                    return {
                        'success': True,
                        'source': 'IPInfo',
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('country', 'N/A'),
                        'region': data.get('region', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'latitude': latitude,
                        'longitude': longitude,
                        'isp': data.get('org', 'N/A'),
                        'organization': data.get('org', 'N/A'),
                        'timezone': data.get('timezone', 'N/A'),
                        'postal': data.get('postal', 'N/A'),
                        'raw_data': data
                    }
                else:
                    return {'success': False, 'error': 'Bogon IP (private/reserved)'}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def analyze_ip(self, ip: str, use_multiple_sources: bool = True) -> Dict:
        """Analisa um IP usando múltiplas fontes para maior precisão"""
        
        # Validação inicial
        if not self.validate_ip(ip):
            return {'success': False, 'error': 'IP inválido'}
        
        if self.is_private_ip(ip):
            return {'success': False, 'error': 'IP privado - não é possível geolocalizar'}
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            
            if use_multiple_sources:
                # Consulta múltiplas APIs
                apis_to_query = ['hackertarget', 'ipapi', 'ipinfo']
                
                for api_name in apis_to_query:
                    task = progress.add_task(f"Consultando {api_name}...", total=None)
                    
                    if api_name == 'hackertarget':
                        result = self.query_hackertarget(ip)
                    elif api_name == 'ipapi':
                        result = self.query_ipapi(ip)
                    elif api_name == 'ipinfo':
                        result = self.query_ipinfo(ip)
                    
                    if result['success']:
                        results.append(result)
                    
                    progress.update(task, completed=True)
                    time.sleep(0.5)  # Rate limiting
            else:
                # Apenas HackerTarget (API principal)
                task = progress.add_task("Consultando HackerTarget...", total=None)
                result = self.query_hackertarget(ip)
                if result['success']:
                    results.append(result)
                progress.update(task, completed=True)
        
        if not results:
            return {'success': False, 'error': 'Nenhuma API retornou dados válidos'}
        
        # Consolida resultados
        consolidated = self.consolidate_results(results)
        
        # Adiciona ao histórico
        self.history.append({
            'timestamp': datetime.now(),
            'ip': ip,
            'result': consolidated
        })
        
        return consolidated
    
    def consolidate_results(self, results: List[Dict]) -> Dict:
        """Consolida resultados de múltiplas APIs para maior precisão"""
        if not results:
            return {'success': False, 'error': 'Nenhum resultado para consolidar'}
        
        if len(results) == 1:
            return results[0]
        
        # Consolida dados de múltiplas fontes
        consolidated = {
            'success': True,
            'sources': [r['source'] for r in results],
            'ip': results[0]['ip'],
            'country': self.get_most_common([r.get('country', 'N/A') for r in results]),
            'country_code': self.get_most_common([r.get('country_code', 'N/A') for r in results]),
            'region': self.get_most_common([r.get('region', 'N/A') for r in results]),
            'city': self.get_most_common([r.get('city', 'N/A') for r in results]),
            'latitude': self.get_average_coordinate([r.get('latitude', 'N/A') for r in results]),
            'longitude': self.get_average_coordinate([r.get('longitude', 'N/A') for r in results]),
            'isp': self.get_most_common([r.get('isp', 'N/A') for r in results]),
            'organization': self.get_most_common([r.get('organization', 'N/A') for r in results]),
            'timezone': self.get_most_common([r.get('timezone', 'N/A') for r in results]),
            'confidence': self.calculate_confidence(results),
            'all_results': results
        }
        
        return consolidated
    
    def get_most_common(self, values: List[str]) -> str:
        """Retorna o valor mais comum em uma lista"""
        values = [v for v in values if v and v != 'N/A']
        if not values:
            return 'N/A'
        
        from collections import Counter
        counter = Counter(values)
        return counter.most_common(1)[0][0]
    
    def get_average_coordinate(self, coordinates: List[str]) -> str:
        """Calcula a média das coordenadas"""
        valid_coords = []
        for coord in coordinates:
            try:
                if coord and coord != 'N/A':
                    valid_coords.append(float(coord))
            except (ValueError, TypeError):
                continue
        
        if not valid_coords:
            return 'N/A'
        
        return str(round(sum(valid_coords) / len(valid_coords), 6))
    
    def calculate_confidence(self, results: List[Dict]) -> str:
        """Calcula a confiança baseada na consistência dos resultados"""
        if len(results) == 1:
            return "Média (1 fonte)"
        
        # Verifica consistência dos dados principais
        countries = [r.get('country', '') for r in results]
        cities = [r.get('city', '') for r in results]
        
        country_consistency = len(set(countries)) == 1
        city_consistency = len(set(cities)) == 1
        
        if country_consistency and city_consistency:
            return f"Alta ({len(results)} fontes concordam)"
        elif country_consistency:
            return f"Média ({len(results)} fontes, país consistente)"
        else:
            return f"Baixa ({len(results)} fontes divergem)"
    
    def analyze_batch(self, ips: List[str]) -> List[Dict]:
        """Analisa múltiplos IPs em lote"""
        results = []
        
        console.print(f"\n[bold blue]Analisando {len(ips)} endereços IP...[/bold blue]")
        
        for i, ip in enumerate(ips, 1):
            console.print(f"\n[yellow]Processando {i}/{len(ips)}: {ip}[/yellow]")
            result = self.analyze_ip(ip.strip())
            results.append(result)
            
            # Rate limiting entre requisições
            if i < len(ips):
                time.sleep(1)
        
        return results
    
    def export_results(self, results: List[Dict], filename: str = None) -> str:
        """Exporta resultados para arquivo JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"geoip_results_{timestamp}.json"
        
        filepath = f"/Users/biaphraaraujo/Documents/Python/GeoIP/{filename}"
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'total_analyzed': len(results),
            'results': results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        
        return filepath
    
    def get_history(self) -> List[Dict]:
        """Retorna o histórico de consultas"""
        return self.history
    
    def clear_history(self):
        """Limpa o histórico de consultas"""
        self.history = []
