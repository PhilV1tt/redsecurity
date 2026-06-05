# Présentation BeSecured

## Slide 1. BeSecured

Personal Cybersecurity Risk Scanner.

But : donner à un utilisateur non technique une lecture claire de la posture sécurité locale.

## Slide 2. Problème

- les réglages sécurité sont dispersés
- les outils pros sont trop techniques
- un utilisateur ne sait pas toujours quoi corriger en premier
- un score simple aide à prioriser

## Slide 3. Positionnement

BeSecured est un outil local d’awareness.

Ce n’est pas :

- un pentest
- un antivirus
- un outil de monitoring
- un service cloud

## Slide 4. Workflow

```text
Lancer BeSecured
  -> scan local
  -> score 0 à 100
  -> findings par gravité
  -> conseils de correction
  -> export HTML
```

## Slide 5. Architecture

```text
UI locale / CLI
  -> scanner Python
  -> checks OS
  -> score engine
  -> report HTML / JSON
```

Windows, macOS et Linux ont chacun des checks adaptés.

## Slide 6. Checks

Exemples :

- firewall
- ports ouverts
- comptes admin et guest
- password policy
- dossiers partagés
- startup programs
- antivirus ou protections natives
- updates
- chiffrement disque

## Slide 7. Scoring

Statuts :

- `OK` : 0 point perdu
- `WARN` : 2 points perdus
- `CRIT` : 5 points perdus
- `INFO` et `SKIP` : visibles mais non scorés

Formule :

```text
100 - round(lost_points / max_points * 100)
```

## Slide 8. Privacy

- tout tourne sur la machine
- pas de compte
- pas de backend
- pas d’upload
- rapports générés localement

## Slide 9. Démo

1. Lancer `python -m besecured.ui`.
2. Cliquer sur `Start scan`.
3. Lire le score.
4. Ouvrir `Issues`.
5. Exporter le rapport HTML.

## Slide 10. Conclusion

BeSecured donne une lecture claire du risque local.

Le projet reste volontairement limité : awareness, priorisation, remédiation manuelle.
