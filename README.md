# BeSecured

BeSecured est un scanner local de posture cybersécurité pour le projet P12 Personal Cybersecurity Risk Scanner.

L’objectif est simple : aider un utilisateur non technique à comprendre les faiblesses courantes de sa machine, avec un score lisible, des constats classés par gravité et des conseils de correction concrets.

BeSecured est un outil de sensibilisation. Ce n’est pas un outil de pentest, pas un antivirus, pas un système de surveillance continue et pas un service cloud.

## Installation

Prérequis :

- Python 3.10 ou plus
- Windows, macOS ou Linux
- Un terminal local

Sur Windows, installer Python depuis `www.python.org/downloads`, puis cocher `Add Python to PATH`.

Cloner ou dézipper le projet, puis se placer à la racine du repo.

Installation optionnelle en mode modifiable :

```bash
python -m pip install -e .
```

Si la commande `python` n’existe pas sur macOS ou Linux, utiliser `python3`.

## Usage application native

C’est la façon recommandée de lancer BeSecured. L’interface s’ouvre dans une vraie fenêtre d’application, sans navigateur ni barre d’adresse, via le webview natif de l’OS. WKWebView sur macOS, WebView2 sur Windows.

Installer les dépendances puis lancer :

```bash
python -m pip install -e .
python -m besecured.app
```

Dans ce mode, le scan et l’export passent par un pont interne entre l’interface et le moteur Python. Aucun serveur ni port local n’est ouvert.

L’export écrit le rapport dans un dossier local d’application et l’interface affiche le chemin du fichier :

- macOS : `~/Library/Application Support/BeSecured/Reports/`
- Windows : `%LOCALAPPDATA%\BeSecured\Reports\`
- Linux : `~/.local/state/besecured/reports/`

Sur Linux, le webview natif demande les paquets système PyGObject et WebKit2GTK.

## Usage interface web (mode développement)

Ce mode sert au développement et de solution de repli. Il expose l’UI par un petit serveur local sur `127.0.0.1`, sans pywebview.

Lancer l’interface locale :

```bash
python -m besecured.ui
```

Sur Windows, si nécessaire :

```powershell
py -m besecured.ui
```

Le serveur ouvre l’interface dans une fenêtre dédiée, sans barre d’adresse ni onglets, quand Chrome, Edge ou un équivalent est présent. Sinon il bascule sur le navigateur par défaut. Pour forcer l’ouverture dans un onglet classique, ajouter `--browser`. Si rien ne s’ouvre, copier l’adresse affichée dans le terminal, par exemple `127.0.0.1:53921`.

Dans l’interface :

1. Cliquer sur `Lancer le scan`.
2. Attendre la fin du scan.
3. Lire le score et les catégories.
4. Ouvrir `Points à corriger` pour les détails.
5. Ouvrir `Rapport` pour exporter un rapport HTML.

Pour arrêter l’interface, revenir au terminal et faire `Ctrl+C`.

## Usage CLI

Lancer un scan et générer un rapport HTML local :

```bash
python -m besecured
```

Générer un JSON :

```bash
python -m besecured --format json --output BeSecured_Report.json
```

Générer HTML plus JSON :

```bash
python -m besecured --json-output BeSecured_Report.json
```

Par défaut, BeSecured écrit les rapports dans un dossier local d’application, pas dans un dossier cloud synchronisé.

## Plateformes

| Plateforme | Statut | Notes |
|---|---|---|
| Windows | support principal | Firewall, Defender, UAC, comptes locaux, partages, updates, BitLocker selon disponibilité |
| macOS | support partiel | Firewall, FileVault, Gatekeeper, SIP, XProtect, users, sharing, launch items |
| Linux | support partiel | Firewall courant, updates package manager, users, sudo, shares, startup, LUKS selon outils disponibles |

Quand un check n’est pas disponible ou demande plus de privilèges, il est marqué `SKIP` ou `INFO` au lieu de faire semblant de réussir.

## Checks

BeSecured lance des checks non intrusifs :

- ports TCP en écoute et services risqués comme RDP, SMB, SSH, VNC, bases de données
- firewall local
- fraîcheur des mises à jour système
- comptes administrateur et comptes invités
- règles de mot de passe quand elles sont lisibles
- dossiers partagés SMB, NFS ou équivalent OS
- programmes de démarrage et chemins suspects
- antivirus ou protections natives disponibles
- chiffrement disque
- UAC sur Windows, Gatekeeper et SIP sur macOS

Les checks lisent l’état local. Ils ne lancent pas d’exploitation, ne forcent pas de connexion et ne modifient pas la machine.

## Scoring

Le score va de 0 à 100.

Seuls les statuts `OK`, `WARN` et `CRIT` changent le score.

| Statut | Poids |
|---|---:|
| OK | 0 point perdu |
| WARN | 2 points perdus |
| CRIT | 5 points perdus |
| INFO | ignoré |
| SKIP | ignoré |

Formule :

```text
score = 100 - round(lost_points / max_points * 100)
```

Le rapport affiche aussi les points perdus par catégorie et les checks qui impactent le plus le score.

Grades :

| Score | Grade |
|---:|---|
| 90 à 100 | A |
| 75 à 89 | B |
| 60 à 74 | C |
| 40 à 59 | D |
| 0 à 39 | F |

## Confidentialité

BeSecured fonctionne tout en local :

- pas de compte
- pas de backend externe
- pas d’API cloud
- pas d’upload de fichiers, credentials ou détails système
- rapport HTML et JSON générés localement

En mode natif, l’interface parle au moteur par un pont interne, sans serveur ni port ouvert. En mode web de développement, le serveur écoute sur `127.0.0.1` et expose seulement un point d’accès local de scan.

## Limites

BeSecured ne remplace pas un audit sécurité professionnel.

Limites assumées :

- pas de pentest
- pas de scan réseau agressif
- pas de bruteforce
- pas d’exploitation
- pas de remédiation automatique
- pas de surveillance continue
- pas de garantie que tous les antivirus ou outils EDR soient détectés
- certains checks dépendent des commandes disponibles et des droits utilisateur

Le but est de donner une lecture claire du risque local, pas de prouver qu’une machine est sûre.

## Architecture

```text
Local UI or CLI
  -> Python scanner engine
  -> OS specific checks
  -> Risk scoring
  -> HTML or JSON report
```

Structure principale :

| Chemin | Rôle |
|---|---|
| `besecured/scanner.py` | orchestre le scan |
| `besecured/checks/common.py` | checks communs et helpers |
| `besecured/checks/windows.py` | checks Windows |
| `besecured/checks/macos.py` | checks macOS |
| `besecured/checks/linux.py` | checks Linux |
| `besecured/models.py` | objets `Finding` et `ScanResult` |
| `besecured/scoring.py` | score, grade, détails de calcul |
| `besecured/report.py` | export HTML et JSON |
| `besecured/app.py` | application native pywebview, pont vers le moteur |
| `besecured/ui/` | serveur local de développement et interface |
| `packaging/` | spec PyInstaller et icônes de l’application |
| `tests/` | tests unitaires et contrat UI |
| `legacy/` | documents école et anciens scripts PowerShell |

## Construction d’un exécutable

Pour distribuer BeSecured sans installation de Python, on construit un binaire double-cliquable avec PyInstaller. Le spec est versionné dans `packaging/BeSecured.spec`.

```bash
python -m pip install pyinstaller
pyinstaller packaging/BeSecured.spec
```

Sortie : `dist/BeSecured.app` sur macOS, `dist/BeSecured/BeSecured.exe` sur Windows. PyInstaller ne fait pas de compilation croisée, le `.app` se construit sur macOS et le `.exe` sur Windows.

Les binaires ne sont pas signés. Au premier lancement, macOS et Windows affichent un avertissement. Sur macOS, clic droit puis Ouvrir. Sur Windows, Informations complémentaires puis Exécuter quand même.

## Tests

Lancer les tests :

```bash
python -m unittest discover -s tests
```

La suite couvre :

- parsers Windows, macOS, Linux et réseau
- scoring
- export report
- contrat JSON UI
- endpoint local `/api/scan`
- absence de dépendances distantes dans les sources sensibles

## Legacy

Les documents école initiaux et les scripts PowerShell MVP sont conservés dans `legacy/`.

Ils restent utiles pour comprendre l’historique du projet, mais la base actuelle est le moteur Python multi OS avec UI locale.

## Rendu

Livrables prêts dans le repo :

- code Python, application native pywebview et UI web de développement
- packaging PyInstaller dans `packaging/` et conception dans `docs/conception-application-native.md`
- README complet
- rapport projet dans `docs/rapport-projet.md`
- trame de présentation dans `docs/presentation.md`
- anciens livrables école rangés dans `legacy/`
