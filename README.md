# BeSecured

<p align="center">
  <img src="docs/coucou-reda.svg" alt="Coucou Reda" width="760">
</p>

BeSecured est un prototype d’interface locale pour lancer un diagnostic cybersécurité simple.

Le but pour la démo : ouvrir l’UI dans le navigateur, lancer le scan local, afficher le score, les catégories, les alertes et le rapport.

Tout tourne sur la machine. Pas de compte, pas de cloud, pas d’upload.

## Lancer l’interface

Il faut Python 3.10 ou plus.

Sur Windows, installe Python depuis :

```text
www.python.org/downloads
```

Pendant l’installation, coche `Add Python to PATH`.

Ensuite, dézippe le projet, ouvre un terminal dans le dossier BeSecured, puis lance :

```powershell
python -m besecured.ui
```

Si Windows ne trouve pas `python`, utilise :

```powershell
py -m besecured.ui
```

Sur macOS ou Linux :

```bash
python3 -m besecured.ui
```

Une page locale doit s’ouvrir dans le navigateur.

Si rien ne s’ouvre, copie l’adresse affichée dans le terminal. Elle ressemble à ça :

```text
127.0.0.1:53921
```

Pour arrêter l’interface, retourne dans le terminal et fais `Ctrl+C`.

## Ce que Reda doit tester

Dans l’interface :

1. Clique sur `Start scan`.
2. Attends la fin de la progression.
3. Regarde le score de risque.
4. Ouvre l’onglet `Issues`.
5. Ouvre l’onglet `Report`.
6. Vérifie que l’export du rapport est visible.

Le bouton `Start scan` appelle le moteur local Python via le serveur UI. Le fichier `scan-results.json` reste seulement un échantillon de prototype.

## Ce que l’app montre

BeSecured présente :

- un score de sécurité sur 100
- des catégories comme réseau, système, comptes, protection et mises à jour
- des problèmes classés par gravité
- des explications simples
- un rapport local exportable

## Calcul du score

Le score est volontairement simple et explicable. Il n’utilise pas de ML.

Seuls les contrôles `OK`, `WARN` et `CRIT` comptent dans le score. Les contrôles `INFO` et `SKIP` sont affichés pour la transparence, mais ils ne retirent pas de points.

Poids utilisés :

- `OK` : 0 point perdu
- `WARN` : 2 points perdus
- `CRIT` : 5 points perdus

Formule :

```text
score = 100 - round(points_perdus / points_max * 100)
```

Chaque contrôle scoré peut perdre au maximum 5 points de gravité. Exemple : 10 contrôles scorés donnent `points_max = 50`. Si les findings retirent 13 points, le score est `100 - round(13 / 50 * 100) = 74`.

Le rapport affiche aussi les catégories qui impactent le score, les points perdus par catégorie, les poids de gravité et les findings responsables.

Ce n’est pas un outil de pentest. L’app ne force rien, ne modifie rien et ne récupère pas les données de Reda.

## Lancer le moteur sans UI

Le moteur local peut aussi tourner en ligne de commande.

```bash
python -m besecured
```
