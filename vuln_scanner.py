import nmap
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
import time
import re

app = typer.Typer()
console = Console()

class VulnerabilityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {
            'target': '',
            'scan_time': '',
            'open_ports': [],
            'os_info': '',
            'vulnerabilities': [],
            'active_hosts': []
        }
        # Liste des services communs et leurs ports par défaut
        self.common_services = {
            'http': [80, 8080, 8443],
            'https': [443, 8443],
            'ssh': [22],
            'ftp': [21],
            'smtp': [25, 465, 587],
            'pop3': [110, 995],
            'imap': [143, 993],
            'rdp': [3389],
            'vnc': [5900],
            'mysql': [3306],
            'postgresql': [5432],
            'mssql': [1433],
            'oracle': [1521],
            'dns': [53],
            'smb': [139, 445],
            'telnet': [23]
        }

    def clean_version(self, version: str) -> str:
        """Nettoie la version pour une meilleure correspondance"""
        # Extraction du numéro de version
        version_match = re.search(r'(\d+\.\d+(\.\d+)?)', version)
        if version_match:
            return version_match.group(1)
        return version

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
            scan_args = '-sV -O --version-intensity 7'  # Scan de base avec détection de version approfondie
            if scan_type == "aggressive":
                scan_args = '-sV -O -A -T4 --version-intensity 9'
            elif scan_type == "stealth":
                scan_args = '-sV -O -T2 --version-intensity 5'
            
            # Scan des ports
            self.nm.scan(target, arguments=scan_args)
            
            # Mise à jour des résultats
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        if service['state'] == 'open':  # Ne garder que les ports ouverts
                            version = service.get('version', 'unknown')
                            if version != 'unknown':
                                version = self.clean_version(version)
                            
                            self.results['open_ports'].append({
                                'port': port,
                                'state': service['state'],
                                'service': service['name'].lower(),
                                'version': version,
                                'protocol': proto,
                                'product': service.get('product', ''),
                                'extrainfo': service.get('extrainfo', '')
                            })
                
                # Détection OS avec gestion d'erreur
                try:
                    if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                        self.results['os_info'] = self.nm[host]['osmatch'][0]['name']
                    else:
                        self.results['os_info'] = 'Inconnu'
                except (IndexError, KeyError):
                    self.results['os_info'] = 'Inconnu'
            
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
                    # Construction des termes de recherche
                    search_terms = set()
                    
                    # Ajout des termes de recherche basés sur le service et la version
                    if port_info['service']:
                        search_terms.add(f"{port_info['service']} {port_info['version']}")
                        search_terms.add(port_info['service'])
                    
                    # Ajout des termes basés sur le produit si disponible
                    if port_info['product']:
                        search_terms.add(f"{port_info['product']} {port_info['version']}")
                        search_terms.add(port_info['product'])
                    
                    for search_term in search_terms:
                        try:
                            time.sleep(0.5)  # Respect des limites de l'API
                            
                            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={search_term}"
                            headers = {
                                'User-Agent': 'VulnerabilityScanner/1.0',
                                'Accept': 'application/json'
                            }
                            
                            response = requests.get(url, headers=headers, timeout=10)
                            
                            if response.status_code == 200:
                                data = response.json()
                                total_results = data.get('totalResults', 0)
                                
                                if total_results > 0:
                                    for cve in data.get('result', {}).get('CVE_Items', []):
                                        cve_id = cve['cve']['CVE_data_meta']['ID']
                                        
                                        # Vérification si la CVE est déjà dans la liste
                                        if not any(v['cve_id'] == cve_id for v in self.results['vulnerabilities']):
                                            description = cve['cve']['description']['description_data'][0]['value']
                                            
                                            # Récupération de la sévérité
                                            severity = 'UNKNOWN'
                                            cvss_v3 = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
                                            if cvss_v3:
                                                severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
                                            else:
                                                cvss_v2 = cve.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})
                                                if cvss_v2:
                                                    severity = cvss_v2.get('severity', 'UNKNOWN')
                                            
                                            self.results['vulnerabilities'].append({
                                                'cve_id': cve_id,
                                                'service': port_info['service'],
                                                'version': port_info['version'],
                                                'severity': severity,
                                                'description': description,
                                                'port': port_info['port'],
                                                'search_term': search_term,
                                                'product': port_info['product']
                                            })
                                            
                                            console.print(f"[yellow]CVE trouvée : {cve_id} ({severity}) - {port_info['service']} {port_info['version']}[/yellow]")
                            
                        except requests.RequestException as e:
                            console.print(f"[yellow]Avertissement : Erreur lors de la recherche de vulnérabilités pour {search_term}[/yellow]")
                            continue
                        except Exception as e:
                            console.print(f"[red]Erreur inattendue : {str(e)}[/red]")
                            continue
                
                progress.update(task, advance=1)
            
            # Tri des vulnérabilités par sévérité
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            self.results['vulnerabilities'].sort(key=lambda x: severity_order.get(x['severity'], 5))

    def generate_report(self, output_dir: Optional[str] = None):
        """Génère un rapport HTML"""
        console.print("[bold blue]Génération du rapport...[/bold blue]")
        
        # Création du dossier de rapports par défaut si non spécifié
        if not output_dir:
            output_dir = "scan_reports"
        
        # Création du nom du fichier avec la date et l'heure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{self.results['target'].replace('/', '_')}_{timestamp}.html"
        
        # Création du dossier s'il n'existe pas
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        # Filtrage des ports ouverts
        open_ports = [port for port in self.results['open_ports'] if port['state'] == 'open']
        
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report.html')
        
        html_content = template.render(
            target=self.results['target'],
            scan_time=self.results['scan_time'],
            open_ports=open_ports,  # Utilisation des ports filtrés
            os_info=self.results['os_info'],
            vulnerabilities=self.results['vulnerabilities'],
            active_hosts=self.results['active_hosts']
        )
            
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

def main(
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

if __name__ == "__main__":
    typer.run(main) 