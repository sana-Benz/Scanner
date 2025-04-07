# Scanner de Vulnérabilités

Un scanner de vulnérabilités en Python avec interface CLI, utilisant Nmap pour la détection des services et l'API NIST pour la recherche de vulnérabilités.

## Fonctionnalités

- Scan de réseau pour détecter les hôtes actifs
- Scan de ports (TCP/UDP)
- Fingerprinting des services
- Détection du système d'exploitation
- Recherche de vulnérabilités via l'API NIST
- Génération de rapports HTML modernes et responsifs
- Interface CLI intuitive avec barres de progression

## Prérequis

- Python 3.7+
- Nmap installé sur le système
- Les dépendances Python listées dans `requirements.txt`

## Installation

1. Clonez le dépôt :
```bash
git clone [URL_DU_REPO]
cd [NOM_DU_REPO]
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

3. Assurez-vous que Nmap est installé sur votre système :
- Windows : Téléchargez et installez depuis https://nmap.org/download.html
- Linux : `sudo apt-get install nmap`
- macOS : `brew install nmap`

## Utilisation

### Scan d'une cible unique

```bash
python vuln_scanner.py scan 192.168.1.1
```

### Scan d'un réseau

```bash
python vuln_scanner.py scan 192.168.1.0/24 --network
```

### Options disponibles

- `--type` ou `-t` : Type de scan (normal, aggressive, stealth)
- `--save` ou `-s` : Répertoire de sortie pour le rapport
- `--network` ou `-n` : Effectuer un scan de réseau

Exemples :

```bash
# Scan agressif d'une cible
python vuln_scanner.py scan 192.168.1.1 --type aggressive

# Scan furtif d'un réseau avec sauvegarde du rapport
python vuln_scanner.py scan 192.168.1.0/24 --network --type stealth --save reports
```

## Structure du Rapport

Le rapport HTML généré contient :

- Un résumé du scan
- La liste des ports ouverts
- Les détails des services détectés
- Les vulnérabilités identifiées avec leurs CVEs
- Une légende des niveaux de sévérité

## Sécurité

⚠️ **Important** : Ce scanner est conçu pour être utilisé uniquement sur des systèmes dont vous avez l'autorisation de scanner. L'utilisation non autorisée peut être illégale.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une pull request.

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails. 