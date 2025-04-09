import nmap3
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from jinja2 import Environment, FileSystemLoader
import requests
import json
from datetime import datetime
import os
import ipaddress
from typing import Optional, List
import concurrent.futures

app = typer.Typer()
console = Console()

class VulnerabilityScanner:
    def __init__(self):
        self.nm = nmap3.Nmap()
        self.results = {
            'target': '',
            'scan_time': '',
            'open_ports': [],
            'os_info': '',
            'vulnerabilities': [],
            'active_hosts': []
        }

    def scan_network(self, network: str) -> List[str]:
        """Scanne un réseau pour détecter les hôtes actifs"""
        console.print(f"[bold blue]Scan du réseau {network} pour détecter les hôtes actifs...[/bold blue]")
        
        try:
            # Vérification de la validité de l'adresse réseau
            network_obj = ipaddress.ip_network(network)
        except ValueError:
            console.print(f"[red]Erreur : {network} n'est pas une adresse réseau valide[/red]")
            return []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task("Scan du réseau...", total=100)
            
            # Scan des hôtes actifs
            self.nm.scan(hosts=str(network), arguments='-sn')
            
            active_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    active_hosts.append(host)
                    self.results['active_hosts'].append({
                        'ip': host,
                        'hostname': self.nm[host].hostname() or 'Inconnu'
                    })
            
            progress.update(task, completed=100)
            return active_hosts

    def scan_target(self, target: str, scan_type: str = "normal"):
        """Effectue un scan Nmap complet de la cible"""
        self.results['target'] = target
        self.results['scan_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            # Configuration du scan en fonction du type
            scan_args = '-sV -O'  # Scan de base
            if scan_type == "aggressive":
                scan_args = '-sV -O -A -T4'
            elif scan_type == "stealth":
                scan_args = '-sV -O -T2'
            
            # Scan des ports
            self.nm.scan(target, arguments=scan_args)
            
            # Mise à jour des résultats
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        self.results['open_ports'].append({
                            'port': port,
                            'state': service['state'],
                            'service': service['name'],
                            'version': service.get('version', 'unknown'),
                            'protocol': proto
                        })
                
                # Détection OS
                if 'osmatch' in self.nm[host]:
                    self.results['os_info'] = self.nm[host]['osmatch'][0]['name']
            
            progress.update(task, completed=100)

    def check_vulnerabilities(self):
        """Vérifie les vulnérabilités via l'API NIST"""
        console.print("[bold blue]Recherche de vulnérabilités...[/bold blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task("Analyse des vulnérabilités...", total=len(self.results['open_ports']))
            
            for port_info in self.results['open_ports']:
                if port_info['version'] != 'unknown':
                    # Recherche de CVEs via l'API NIST
                    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={port_info['service']} {port_info['version']}"
                    try:
                        response = requests.get(url)
                        if response.status_code == 200:
                            data = response.json()
                            for cve in data.get('result', {}).get('CVE_Items', []):
                                cve_id = cve['cve']['CVE_data_meta']['ID']
                                description = cve['cve']['description']['description_data'][0]['value']
                                severity = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
                                
                                self.results['vulnerabilities'].append({
                                    'cve_id': cve_id,
                                    'service': port_info['service'],
                                    'version': port_info['version'],
                                    'severity': severity,
                                    'description': description,
                                    'port': port_info['port']
                                })
                    except requests.RequestException as e:
                        console.print(f"[yellow]Avertissement : Erreur lors de la recherche de vulnérabilités pour {port_info['service']} {port_info['version']}[/yellow]")
                
                progress.update(task, advance=1)

    def generate_report(self, output_dir: Optional[str] = None):
        """Génère un rapport HTML"""
        console.print("[bold blue]Génération du rapport...[/bold blue]")
        
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report.html')
        
        html_content = template.render(
            target=self.results['target'],
            scan_time=self.results['scan_time'],
            open_ports=self.results['open_ports'],
            os_info=self.results['os_info'],
            vulnerabilities=self.results['vulnerabilities'],
            active_hosts=self.results['active_hosts']
        )
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        else:
            output_path = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        console.print(f"[green]Rapport généré avec succès : {output_path}")

    def display_summary(self):
        """Affiche un résumé des résultats dans le terminal"""
        table = Table(title="Résumé du Scan")
        table.add_column("Type", style="cyan")
        table.add_column("Valeur", style="magenta")
        
        table.add_row("Cible", self.results['target'])
        table.add_row("Date du scan", self.results['scan_time'])
        table.add_row("OS détecté", self.results['os_info'])
        table.add_row("Ports ouverts", str(len(self.results['open_ports'])))
        table.add_row("Vulnérabilités", str(len(self.results['vulnerabilities'])))
        table.add_row("Hôtes actifs", str(len(self.results['active_hosts'])))
        
        console.print(table)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Adresse IP, nom d'hôte ou réseau CIDR à scanner"),
    scan_type: str = typer.Option("normal", "--type", "-t", help="Type de scan: normal, aggressive, stealth"),
    output_dir: Optional[str] = typer.Option(None, "--save", "-s", help="Répertoire de sortie pour le rapport"),
    network_scan: bool = typer.Option(False, "--network", "-n", help="Effectuer un scan de réseau")
):
    """Scanner de vulnérabilités"""
    scanner = VulnerabilityScanner()
    
    try:
        # Vérification si c'est une adresse réseau
        if network_scan or '/' in target:
            active_hosts = scanner.scan_network(target)
            if not active_hosts:
                console.print("[red]Aucun hôte actif trouvé[/red]")
                return
            
            console.print(f"[green]Hôtes actifs trouvés : {len(active_hosts)}[/green]")
            for host in active_hosts:
                console.print(f"[blue]Scan de {host}...[/blue]")
                scanner.scan_target(host, scan_type)
                scanner.check_vulnerabilities()
        else:
            console.print(f"[bold blue]Démarrage du scan de {target}[/bold blue]")
            scanner.scan_target(target, scan_type)
            scanner.check_vulnerabilities()
        
        scanner.display_summary()
        scanner.generate_report(output_dir)
        
    except Exception as e:
        console.print(f"[red]Erreur lors du scan : {str(e)}[/red]")

def main():
    app()

if __name__ == "__main__":
    main() 