# BeSecured

<p align="center">
  <img src="docs/coucou-reda.svg" alt="Coucou Reda" width="760">
</p>

BeSecured est un prototype d’interface locale pour montrer un diagnostic cybersécurité simple.

Le but pour la démo : ouvrir l’UI dans le navigateur, lancer le scan preview, afficher le score, les catégories, les alertes et le rapport.

Tout tourne sur la machine. Pas de compte, pas de cloud, pas d’upload.

## Lancer l’interface

Il faut Python 3.10 ou plus.

Sur Windows, installe Python depuis :

```text
https://www.python.org/downloads/
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
http://127.0.0.1:53921/
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

Pour l’instant, l’UI charge des résultats locaux de démo depuis `scan-results.json`. C’est normal : l’objectif ici est de montrer l’expérience utilisateur.

## Ce que l’app montre

BeSecured présente :

- un score de sécurité sur 100
- des catégories comme réseau, système, comptes, protection et mises à jour
- des problèmes classés par gravité
- des explications simples
- un rapport local exportable

Ce n’est pas un outil de pentest. L’app ne force rien, ne modifie rien et ne récupère pas les données de Reda.

## Si tu veux lancer le scan moteur

Le moteur local existe aussi, mais ce n’est pas le point principal de la démo UI.

```bash
python -m besecured
```
