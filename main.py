#!/usr/bin/env python3
"""
GeoIP Analyzer - Menu Interativo
Sistema de Geolocalização de IP para Analistas de Segurança
Desenvolvido por Biaphra Araujo
"""

import os
import sys
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
import json

from geoip_analyzer import GeoIPAnalyzer

console = Console()

class GeoIPMenu:
    """Interface de menu interativo para o GeoIP Analyzer"""
    
    def __init__(self):
        self.analyzer = GeoIPAnalyzer()
        self.running = True
    
    def show_banner(self):
        """Exibe o banner do sistema"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                     GeoIP Analyzer v1.0                     ║
║              Sistema de Geolocalização de IP                ║
║                                                              ║
║  Desenvolvido por: Biaphra Araujo                          ║
║  Suporte: IPv4 e IPv6 | Múltiplas APIs | Alta Precisão     ║
╚══════════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold cyan")
    
    def show_menu(self):
        """Exibe o menu principal"""
        menu_panel = Panel(
            """[bold white]MENU PRINCIPAL[/bold white]

[bold green]1.[/bold green] Analisar IP único
[bold green]2.[/bold green] Análise em lote (múltiplos IPs)
[bold green]3.[/bold green] Histórico de consultas
[bold green]4.[/bold green] Exportar resultados
[bold green]5.[/bold green] Configurações
[bold green]6.[/bold green] Sobre o sistema
[bold red]0.[/bold red] Sair

[dim]Digite o número da opção desejada:[/dim]""",
            title="🌍 GeoIP Analyzer",
            border_style="blue"
        )
        console.print(menu_panel)
    
    def analyze_single_ip(self):
        """Analisa um único endereço IP"""
        console.print("\n[bold blue]═══ ANÁLISE DE IP ÚNICO ═══[/bold blue]")
        
        while True:
            ip = Prompt.ask("\n[yellow]Digite o endereço IP (IPv4 ou IPv6)[/yellow]")
            
            if ip.lower() in ['sair', 'exit', 'voltar']:
                break
            
            if not ip.strip():
                console.print("[red]❌ IP não pode estar vazio![/red]")
                continue
            
            # Pergunta sobre usar múltiplas fontes
            use_multiple = Confirm.ask(
                "\n[cyan]Usar múltiplas APIs para maior precisão?[/cyan]",
                default=True
            )
            
            console.print(f"\n[green]🔍 Analisando IP: {ip}[/green]")
            
            result = self.analyzer.analyze_ip(ip, use_multiple_sources=use_multiple)
            
            if result['success']:
                self.display_ip_result(result)
                
                # Pergunta se quer analisar outro IP
                if not Confirm.ask("\n[cyan]Analisar outro IP?[/cyan]", default=False):
                    break
            else:
                console.print(f"\n[red]❌ Erro: {result['error']}[/red]")
                
                if not Confirm.ask("\n[cyan]Tentar outro IP?[/cyan]", default=True):
                    break
    
    def display_ip_result(self, result: dict):
        """Exibe o resultado da análise de IP em formato tabular"""
        
        # Tabela principal com informações de localização
        table = Table(title=f"📍 Geolocalização do IP: {result['ip']}", show_header=True)
        table.add_column("Campo", style="cyan", width=20)
        table.add_column("Valor", style="white", width=40)
        
        # Dados básicos
        table.add_row("🌍 País", result.get('country', 'N/A'))
        table.add_row("🏴 Código do País", result.get('country_code', 'N/A'))
        table.add_row("🏛️ Região/Estado", result.get('region', 'N/A'))
        table.add_row("🏙️ Cidade", result.get('city', 'N/A'))
        table.add_row("📍 Latitude", result.get('latitude', 'N/A'))
        table.add_row("📍 Longitude", result.get('longitude', 'N/A'))
        table.add_row("🌐 ISP", result.get('isp', 'N/A'))
        table.add_row("🏢 Organização", result.get('organization', 'N/A'))
        table.add_row("🕐 Timezone", result.get('timezone', 'N/A'))
        
        # Informações adicionais se disponíveis
        if 'zip_code' in result:
            table.add_row("📮 CEP", result.get('zip_code', 'N/A'))
        if 'as_number' in result:
            table.add_row("🔢 AS Number", result.get('as_number', 'N/A'))
        
        # Informações de confiança
        if 'confidence' in result:
            table.add_row("✅ Confiança", result.get('confidence', 'N/A'))
        if 'sources' in result:
            sources = ', '.join(result['sources'])
            table.add_row("📊 Fontes", sources)
        
        console.print(table)
        
        # Links úteis
        lat = result.get('latitude', '')
        lon = result.get('longitude', '')
        
        if lat != 'N/A' and lon != 'N/A':
            google_maps = f"https://www.google.com/maps?q={lat},{lon}"
            console.print(f"\n[blue]🗺️  Google Maps: {google_maps}[/blue]")
        
        # Informações de segurança
        if self.analyzer.is_private_ip(result['ip']):
            console.print("\n[yellow]⚠️  IP Privado detectado[/yellow]")
        
        # Exibe dados brutos se múltiplas fontes
        if 'all_results' in result and len(result['all_results']) > 1:
            if Confirm.ask("\n[cyan]Exibir dados detalhados de todas as fontes?[/cyan]", default=False):
                self.show_detailed_sources(result['all_results'])
    
    def show_detailed_sources(self, all_results: List[dict]):
        """Exibe dados detalhados de todas as fontes"""
        for i, source_result in enumerate(all_results, 1):
            console.print(f"\n[bold yellow]═══ Fonte {i}: {source_result['source']} ═══[/bold yellow]")
            
            table = Table(show_header=True)
            table.add_column("Campo", style="cyan")
            table.add_column("Valor", style="white")
            
            for key, value in source_result.items():
                if key not in ['success', 'source', 'raw_data', 'all_results']:
                    table.add_row(key.replace('_', ' ').title(), str(value))
            
            console.print(table)
    
    def analyze_batch_ips(self):
        """Analisa múltiplos IPs em lote"""
        console.print("\n[bold blue]═══ ANÁLISE EM LOTE ═══[/bold blue]")
        
        # Opções de entrada
        console.print("\n[yellow]Opções de entrada:[/yellow]")
        console.print("1. Digite IPs manualmente (separados por vírgula)")
        console.print("2. Carregar de arquivo de texto")
        
        option = Prompt.ask("\nEscolha uma opção", choices=["1", "2"], default="1")
        
        ips = []
        
        if option == "1":
            ip_input = Prompt.ask("\n[yellow]Digite os IPs separados por vírgula[/yellow]")
            ips = [ip.strip() for ip in ip_input.split(',') if ip.strip()]
        
        elif option == "2":
            filename = Prompt.ask("\n[yellow]Nome do arquivo (deve estar no diretório atual)[/yellow]")
            filepath = f"/Users/biaphraaraujo/Documents/Python/GeoIP/{filename}"
            
            try:
                with open(filepath, 'r') as f:
                    ips = [line.strip() for line in f if line.strip()]
                console.print(f"[green]✅ Carregados {len(ips)} IPs do arquivo[/green]")
            except FileNotFoundError:
                console.print(f"[red]❌ Arquivo não encontrado: {filepath}[/red]")
                return
            except Exception as e:
                console.print(f"[red]❌ Erro ao ler arquivo: {e}[/red]")
                return
        
        if not ips:
            console.print("[red]❌ Nenhum IP válido fornecido![/red]")
            return
        
        # Confirma a análise
        if not Confirm.ask(f"\n[cyan]Analisar {len(ips)} endereços IP?[/cyan]", default=True):
            return
        
        # Executa análise em lote
        results = self.analyzer.analyze_batch(ips)
        
        # Exibe resumo
        self.show_batch_summary(results)
        
        # Pergunta sobre exportar
        if Confirm.ask("\n[cyan]Exportar resultados para arquivo JSON?[/cyan]", default=True):
            filepath = self.analyzer.export_results(results)
            console.print(f"[green]✅ Resultados exportados para: {filepath}[/green]")
    
    def show_batch_summary(self, results: List[dict]):
        """Exibe resumo da análise em lote"""
        successful = [r for r in results if r.get('success', False)]
        failed = [r for r in results if not r.get('success', False)]
        
        # Estatísticas
        stats_table = Table(title="📊 Resumo da Análise em Lote")
        stats_table.add_column("Métrica", style="cyan")
        stats_table.add_column("Valor", style="white")
        
        stats_table.add_row("Total de IPs", str(len(results)))
        stats_table.add_row("Sucessos", f"[green]{len(successful)}[/green]")
        stats_table.add_row("Falhas", f"[red]{len(failed)}[/red]")
        stats_table.add_row("Taxa de Sucesso", f"{len(successful)/len(results)*100:.1f}%")
        
        console.print(stats_table)
        
        # Resultados bem-sucedidos
        if successful:
            console.print("\n[bold green]✅ IPs Analisados com Sucesso:[/bold green]")
            
            results_table = Table()
            results_table.add_column("IP", style="cyan")
            results_table.add_column("País", style="white")
            results_table.add_column("Cidade", style="white")
            results_table.add_column("ISP", style="yellow")
            
            for result in successful[:10]:  # Mostra apenas os primeiros 10
                results_table.add_row(
                    result['ip'],
                    result.get('country', 'N/A'),
                    result.get('city', 'N/A'),
                    result.get('isp', 'N/A')[:30] + "..." if len(result.get('isp', '')) > 30 else result.get('isp', 'N/A')
                )
            
            console.print(results_table)
            
            if len(successful) > 10:
                console.print(f"[dim]... e mais {len(successful) - 10} resultados[/dim]")
        
        # Falhas
        if failed:
            console.print("\n[bold red]❌ IPs com Falha:[/bold red]")
            
            for result in failed:
                console.print(f"  • {result.get('ip', 'N/A')}: {result.get('error', 'Erro desconhecido')}")
    
    def show_history(self):
        """Exibe o histórico de consultas"""
        console.print("\n[bold blue]═══ HISTÓRICO DE CONSULTAS ═══[/bold blue]")
        
        history = self.analyzer.get_history()
        
        if not history:
            console.print("[yellow]📝 Nenhuma consulta no histórico[/yellow]")
            return
        
        # Tabela do histórico
        history_table = Table(title=f"📋 Últimas {len(history)} Consultas")
        history_table.add_column("Data/Hora", style="cyan")
        history_table.add_column("IP", style="white")
        history_table.add_column("País", style="green")
        history_table.add_column("Cidade", style="yellow")
        history_table.add_column("Status", style="white")
        
        for entry in reversed(history[-20:]):  # Últimas 20 consultas
            timestamp = entry['timestamp'].strftime("%d/%m/%Y %H:%M:%S")
            result = entry['result']
            
            status = "✅ Sucesso" if result.get('success') else "❌ Falha"
            country = result.get('country', 'N/A') if result.get('success') else 'N/A'
            city = result.get('city', 'N/A') if result.get('success') else 'N/A'
            
            history_table.add_row(timestamp, entry['ip'], country, city, status)
        
        console.print(history_table)
        
        # Opções do histórico
        console.print("\n[yellow]Opções:[/yellow]")
        console.print("1. Ver detalhes de uma consulta")
        console.print("2. Exportar histórico")
        console.print("3. Limpar histórico")
        console.print("0. Voltar")
        
        option = Prompt.ask("\nEscolha uma opção", choices=["0", "1", "2", "3"], default="0")
        
        if option == "1":
            self.show_history_details(history)
        elif option == "2":
            self.export_history(history)
        elif option == "3":
            if Confirm.ask("[red]Tem certeza que deseja limpar o histórico?[/red]", default=False):
                self.analyzer.clear_history()
                console.print("[green]✅ Histórico limpo com sucesso[/green]")
    
    def show_history_details(self, history: List[dict]):
        """Exibe detalhes de uma consulta específica do histórico"""
        if not history:
            return
        
        # Lista IPs para seleção
        console.print("\n[yellow]Consultas disponíveis:[/yellow]")
        for i, entry in enumerate(reversed(history[-10:]), 1):
            timestamp = entry['timestamp'].strftime("%d/%m/%Y %H:%M:%S")
            console.print(f"{i}. {entry['ip']} - {timestamp}")
        
        try:
            choice = int(Prompt.ask("\nNúmero da consulta")) - 1
            if 0 <= choice < min(10, len(history)):
                selected_entry = list(reversed(history[-10:]))[choice]
                console.print(f"\n[bold green]Detalhes da consulta: {selected_entry['ip']}[/bold green]")
                self.display_ip_result(selected_entry['result'])
            else:
                console.print("[red]❌ Número inválido[/red]")
        except (ValueError, IndexError):
            console.print("[red]❌ Entrada inválida[/red]")
    
    def export_history(self, history: List[dict]):
        """Exporta o histórico para arquivo"""
        if not history:
            console.print("[yellow]📝 Nenhum histórico para exportar[/yellow]")
            return
        
        filename = Prompt.ask(
            "\n[yellow]Nome do arquivo (sem extensão)[/yellow]",
            default="historico_geoip"
        )
        
        filepath = self.analyzer.export_results(
            [entry['result'] for entry in history],
            f"{filename}.json"
        )
        
        console.print(f"[green]✅ Histórico exportado para: {filepath}[/green]")
    
    def show_settings(self):
        """Exibe configurações do sistema"""
        console.print("\n[bold blue]═══ CONFIGURAÇÕES ═══[/bold blue]")
        
        settings_panel = Panel(
            """[bold white]APIs Disponíveis:[/bold white]

[green]✅ HackerTarget[/green] - API principal (gratuita)
[green]✅ IP-API[/green] - API secundária (gratuita)
[green]✅ IPInfo[/green] - API terciária (gratuita)

[bold white]Funcionalidades:[/bold white]
• Suporte IPv4 e IPv6
• Análise com múltiplas fontes
• Consolidação inteligente de resultados
• Cálculo de confiança
• Exportação JSON
• Histórico de consultas

[bold white]Rate Limiting:[/bold white]
• 1 segundo entre consultas em lote
• 0.5 segundos entre APIs
• Timeout de 10 segundos por consulta""",
            title="⚙️ Configurações do Sistema",
            border_style="green"
        )
        
        console.print(settings_panel)
    
    def show_about(self):
        """Exibe informações sobre o sistema"""
        console.print("\n[bold blue]═══ SOBRE O SISTEMA ═══[/bold blue]")
        
        about_panel = Panel(
            """[bold white]GeoIP Analyzer v1.0[/bold white]

[bold cyan]Desenvolvido por:[/bold cyan] Biaphra Araujo
[bold cyan]Especialidade:[/bold cyan] Segurança Cibernética & Análise de Infraestrutura

[bold white]Funcionalidades:[/bold white]
• Geolocalização precisa de endereços IPv4 e IPv6
• Múltiplas APIs para maior confiabilidade
• Interface interativa e intuitiva
• Análise em lote para grandes volumes
• Exportação de resultados
• Histórico de consultas
• Validação rigorosa de entrada

[bold white]Casos de Uso:[/bold white]
• Análise forense digital
• Investigação de incidentes de segurança
• Monitoramento de tráfego suspeito
• Auditoria de infraestrutura
• Threat intelligence

[bold white]APIs Utilizadas:[/bold white]
• HackerTarget GeoIP API
• IP-API.com
• IPInfo.io

[dim]Sistema desenvolvido para analistas de segurança cibernética[/dim]""",
            title="ℹ️ Sobre o GeoIP Analyzer",
            border_style="cyan"
        )
        
        console.print(about_panel)
    
    def run(self):
        """Executa o menu principal"""
        try:
            while self.running:
                console.clear()
                self.show_banner()
                self.show_menu()
                
                choice = Prompt.ask("\n[bold cyan]Sua escolha[/bold cyan]", choices=["0", "1", "2", "3", "4", "5", "6"])
                
                if choice == "0":
                    console.print("\n[bold green]👋 Obrigado por usar o GeoIP Analyzer![/bold green]")
                    self.running = False
                
                elif choice == "1":
                    self.analyze_single_ip()
                    Prompt.ask("\n[dim]Pressione Enter para continuar...[/dim]")
                
                elif choice == "2":
                    self.analyze_batch_ips()
                    Prompt.ask("\n[dim]Pressione Enter para continuar...[/dim]")
                
                elif choice == "3":
                    self.show_history()
                    Prompt.ask("\n[dim]Pressione Enter para continuar...[/dim]")
                
                elif choice == "4":
                    history = self.analyzer.get_history()
                    if history:
                        self.export_history(history)
                    else:
                        console.print("\n[yellow]📝 Nenhum histórico para exportar[/yellow]")
                    Prompt.ask("\n[dim]Pressione Enter para continuar...[/dim]")
                
                elif choice == "5":
                    self.show_settings()
                    Prompt.ask("\n[dim]Pressione Enter para continuar...[/dim]")
                
                elif choice == "6":
                    self.show_about()
                    Prompt.ask("\n[dim]Pressione Enter para continuar...[/dim]")
        
        except KeyboardInterrupt:
            console.print("\n\n[yellow]⚠️ Interrompido pelo usuário[/yellow]")
        except Exception as e:
            console.print(f"\n[red]❌ Erro inesperado: {e}[/red]")
        finally:
            console.print("\n[bold blue]Sistema finalizado.[/bold blue]")

def main():
    """Função principal"""
    menu = GeoIPMenu()
    menu.run()

if __name__ == "__main__":
    main()
