# Rapport projet BeSecured

## Contexte

BeSecured répond au sujet P12 Personal Cybersecurity Risk Scanner.

Le projet part d’un besoin simple : beaucoup d’utilisateurs ne savent pas interpréter l’état sécurité de leur propre machine. Les outils professionnels sont souvent trop techniques, trop lourds ou orientés pentest. BeSecured prend une direction plus limitée : scanner localement quelques signaux importants, calculer un score compréhensible et proposer des actions concrètes.

Le projet ne cherche pas à remplacer un audit professionnel. Il sert d’outil de sensibilisation et d’aide à la correction.

## Objectifs

Objectifs réalisés :

- lancer un scan local depuis une CLI ou une interface locale
- couvrir Windows, macOS et Linux avec des checks adaptés
- produire des findings structurés
- calculer un score 0 à 100
- expliquer le score et les points perdus
- afficher les problèmes par gravité
- exporter un rapport HTML et JSON
- garder les données sur la machine

Objectifs hors périmètre :

- pentest
- exploitation
- bruteforce
- scan réseau agressif
- correction automatique
- surveillance continue
- stockage cloud

## Architecture

Le pipeline actuel est :

```text
Application native, UI web de dev ou CLI
  -> scanner Python
  -> checks communs et spécifiques OS
  -> calcul du score
  -> rapport HTML ou JSON
```

Modules principaux :

| Module | Rôle |
|---|---|
| `besecured/scanner.py` | lance les checks communs puis les checks de l’OS courant |
| `besecured/checks/common.py` | infos système, privilèges, ports ouverts |
| `besecured/checks/windows.py` | firewall, updates, users, policy, shares, startup, Defender, UAC |
| `besecured/checks/macos.py` | firewall, updates, FileVault, users, sharing, launch items, Gatekeeper, SIP, XProtect |
| `besecured/checks/linux.py` | firewall, updates, LUKS, users, password policy, shares, startup, AV |
| `besecured/models.py` | structure des findings et du résultat de scan |
| `besecured/scoring.py` | score global, score par catégorie, détails de calcul |
| `besecured/report.py` | génération HTML et JSON |
| `besecured/app.py` | application native pywebview, pont vers le moteur |
| `besecured/ui/` | serveur local de développement et interface |

## Implémentation

Chaque check retourne un objet `Finding`.

Un finding contient :

- catégorie
- nom du check
- statut `OK`, `WARN`, `CRIT`, `INFO` ou `SKIP`
- détail observé
- explication simple
- action recommandée
- infos de support OS et besoin éventuel de droits admin

Le scanner ne bloque pas si un check est impossible. Il crée un finding `SKIP` avec une explication. C’est important pour rester honnête : un check non disponible n’est pas un check réussi.

## Scoring

Le score part de 100 et retire des points selon les findings scorés.

Poids :

| Statut | Impact |
|---|---:|
| OK | 0 |
| WARN | 2 |
| CRIT | 5 |
| INFO | ignoré |
| SKIP | ignoré |

Formule :

```text
score = 100 - round(lost_points / max_points * 100)
```

Le rapport affiche :

- score final
- grade
- points perdus
- impact par catégorie
- findings qui ont le plus pesé dans le score

Cette formule est volontairement simple. Elle est plus défendable pour un projet de sensibilisation qu’un calcul de score opaque.

## Confidentialité

BeSecured reste local :

- pas de compte utilisateur
- pas de backend distant
- pas d’upload
- pas de cloud
- pas de dépendance à une API externe

La CLI écrit dans un dossier local d’application. En mode natif, l’interface parle au moteur par un pont interne, sans port ouvert. En mode web de développement, l’interface écoute sur `127.0.0.1` et appelle le scanner Python localement.

## Tests

La suite de tests utilise `unittest`.

Commande :

```bash
python -m unittest discover -s tests
```

Les tests couvrent :

- parsers réseau et OS
- scoring
- export HTML
- contrat JSON de l’UI
- serveur local `/api/scan`
- absence de références réseau distantes dans les sources sensibles

Dernière validation locale : 102 tests OK.

## État final

Le rendu final contient :

- moteur Python multi OS
- application native pywebview et interface web de développement
- packaging PyInstaller, `.app` macOS construit en local, `.exe` Windows à construire sur une machine Windows
- rapport HTML exportable
- export JSON
- README complet
- rapport projet
- trame de présentation
- anciens scripts PowerShell rangés comme legacy
- documents école initiaux rangés comme legacy

## Limites

Le projet reste un prototype réaliste, pas un produit sécurité complet.

Limites principales :

- certains checks dépendent des permissions
- certains outils système peuvent manquer
- la détection antivirus est forcément limitée selon OS et environnement
- aucun scan distant n’est lancé
- aucune correction automatique n’est appliquée
- les binaires packagés ne sont pas signés, l’OS affiche un avertissement au premier lancement

## Suite possible

Améliorations utiles :

- build de l’exécutable Windows sur une machine Windows et signature des binaires
- meilleure détection des protections tierces
- historique local des scans, stocké uniquement sur la machine
- profils de scoring plus fins selon usage personnel ou petite organisation
- UI plus guidée pour les remédiations Windows
