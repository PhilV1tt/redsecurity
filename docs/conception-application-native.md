# Conception, passage en application native

Objectif: faire de BeSecured un vrai logiciel qui s'ouvre dans une fenêtre
d'application, pas dans un navigateur web.

## Problème actuel

Aujourd'hui l'UI est un serveur web local (`http.server`) qui sert des fichiers
statiques, et qui s'ouvre soit dans une fenêtre Chrome en mode `--app`, soit
dans un onglet de navigateur. Ça dépend d'un navigateur Chromium installé, ça
expose un port local, et au rendu ça ne ressemble pas à un logiciel.

## Décision

On garde l'UI BeSecured existante (HTML, CSS, JS) et on l'affiche dans une vraie
fenêtre via pywebview, le webview natif de l'OS. WKWebView sur macOS, WebView2
sur Windows. Plus de navigateur, plus d'onglet, plus de barre d'URL.

Le JS ne parle plus au Python par HTTP mais par le pont JS vers Python de
pywebview. Donc plus de serveur ni de port quand l'app tourne en mode natif.

Approches écartées: réécriture complète en widgets natifs (Tkinter ou Qt). Les
deux jettent l'UI déjà faite, et Qt embarque environ 150 Mo. pywebview réutilise
le travail UI et reste léger.

Tauri et Electron sont écartés aussi. Electron embarque Chromium, lourd et cœur
Node. Tauri est léger et utilise le webview natif de l'OS, mais son cœur est en
Rust et ne sait pas exécuter le scanner Python directement. L'utiliser
imposerait soit une réécriture Rust, soit le scanner Python en sidecar avec une
glue Rust et, en pratique, un serveur HTTP local réintroduit. pywebview offre le
même résultat (fenêtre native, webview système, app légère) avec un cœur Python.

## Architecture

Nouveau point d'entrée `besecured/app.py`, lancé par `python -m besecured.app`.
Il crée une fenêtre pywebview qui charge les fichiers statiques de
`besecured/ui/static/`, et expose au JS un objet `Api` avec deux méthodes.

- `run_scan()` retourne `run_scan().to_dict()`, le même dict que l'endpoint
  HTTP actuel.
- `export_report(fmt)` écrit le rapport via `besecured/report.py`
  (`write_html_report` ou `write_json_report`) dans le dossier local documenté,
  et retourne le chemin écrit.

Le moteur de scan ne change pas. `app.py` réutilise `run_scan` et `report.py`
tels quels.

## Modifications de l'UI

Deux changements ciblés dans `besecured/ui/static/app.js`, rien d'autre.

`runLocalScan()` (vers la ligne 561): si `window.pywebview?.api` existe, appeler
`window.pywebview.api.run_scan()`, sinon garder le `fetch("/api/scan")` actuel.

`exportReport()` (vers la ligne 640): si pywebview existe, appeler
`window.pywebview.api.export_report(fmt)`, sinon garder le download par blob
actuel.

Cette double branche garde l'UI fonctionnelle dans les deux modes, app native et
serveur web de dev.

## Export

En mode natif, l'export sauvegarde directement dans le dossier local déjà
annoncé par l'UI, puis l'UI confirme le chemin écrit. Pas de dialogue
"Enregistrer sous".

- macOS: `~/Library/Application Support/BeSecured/Reports/`
- Windows: `%LOCALAPPDATA%\BeSecured\Reports\`
- Linux: `~/.local/state/besecured/reports/`

Ça corrige un écart actuel: l'UI affiche "Saved to the local folder" vers ces
dossiers alors que le code fait en réalité un download navigateur.

## Dépendances

`pywebview` devient une dépendance du projet, parce que l'application native est
le produit livré. Le moteur de scan reste importable sans pywebview pour que les
tests tournent en stdlib pur. En pratique, `app.py` est le seul fichier qui
importe pywebview, et `scanner.py`, `checks/`, `scoring.py`, `report.py` n'y
touchent pas.

Backends pywebview par OS:

- macOS: pyobjc, tiré par pip, rien à installer en plus.
- Windows: runtime WebView2, déjà présent sur Windows 11 et la plupart des
  Windows 10 à jour.
- Linux: PyGObject et WebKit2GTK, paquets système. Hors cible de rendu mais
  documenté.

## Packaging

Outil: PyInstaller. Il embarque Python, pywebview et les fichiers statiques dans
un bundle double-cliquable. `BeSecured.app` sur macOS, `BeSecured.exe` sur
Windows.

Contrainte: PyInstaller ne cross-compile pas. Le `.app` se construit sur macOS,
le `.exe` sur une machine ou VM Windows. Le build macOS se fait en local. Le
build Windows demande une machine Windows côté Phil.

Un binaire packagé démontre le scan de l'OS sur lequel il tourne. L'app macOS
montre les checks macOS, l'exe Windows montre les checks Windows.

## Simplicité pour l'utilisateur

Contrat pour l'utilisateur final: il télécharge un fichier, il double-clique, ça
s'ouvre. Pas d'installation de Python, pas de terminal, pas de dépendances à
gérer. C'est le rôle du bundle PyInstaller.

L'app se lance sans droits administrateur. Les checks qui demandent des
privilèges élevés sont marqués non disponibles plutôt que de forcer un lancement
en admin. Plus simple et plus sûr, et c'est déjà la philosophie du projet.

Seule friction réelle, les binaires non signés déclenchent un avertissement de
l'OS au premier lancement, Gatekeeper sur macOS et SmartScreen sur Windows. La
signature officielle demande un compte payant, Apple Developer ou certificat
Windows. Par défaut on ne signe pas et on documente le contournement en un clic,
clic droit puis Ouvrir sur macOS, Informations complémentaires puis Exécuter
quand même sur Windows. La signature reste une option pour plus tard.

## Conventions de projet

Pour que le repo ressemble à une vraie app OSS et pas à un script lancé à la
main, on aligne quelques conventions.

- Point d'entrée GUI déclaré dans `pyproject.toml` (`gui_scripts`), en plus du
  CLI existant.
- Vraies icônes d'app, `.icns` pour macOS et `.ico` pour Windows, dérivées du
  `favicon.svg`.
- Fichier de spec PyInstaller versionné dans le repo, avec nom d'app, version et
  identifiant de bundle `com.besecured.app`, plutôt qu'une commande à retaper.
- Instructions de build dans le README.

Un fichier LICENSE reste à ajouter au choix de Phil. Non décidé ici.

## Ce qui ne change pas

- Tout le moteur de scan.
- Le serveur web `besecured/ui`, gardé comme harnais de dev et fallback web.
- Le design BeSecured, sauf les deux branches dans `app.js`.
- Les tests existants, dont le contrat `/api/scan`.

## Validation

- Tests existants verts, lancés sans pywebview installé.
- Lancement de `python -m besecured.app`: la fenêtre s'ouvre, le scan tourne par
  le pont, l'export écrit un fichier dans le dossier local et l'UI confirme le
  chemin.
- Build PyInstaller macOS: `BeSecured.app` s'ouvre au double-clic et fait un
  scan complet.

## Ordre de travail

1. `besecured/app.py` avec la fenêtre pywebview et l'objet `Api`.
2. Les deux branches dans `app.js`.
3. `pywebview` et le point d'entrée `gui_scripts` dans `pyproject.toml`, vérifier
   que les tests passent sans pywebview installé.
4. Icônes `.icns` et `.ico`, spec PyInstaller versionné, build macOS.
5. Build Windows sur machine Windows.
