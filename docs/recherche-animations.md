# Animations de l'interface BeSecured: note de recherche

Document destiné à briefer Claude Design, en complément de la note sur l'interface et les couleurs. Objectif: fonder les choix de mouvement sur des preuves, pour un outil de diagnostic de sécurité local, calme, utilisé par des non-techniciens.

Sources principales: littérature HCI sur l'animation et le temps de réponse, standards W3C, guides Material et Apple, recherche sur la performance perçue et le mal des transports visuel, preprints arXiv. Niveau de confiance global: élevé sur le temps de réponse et l'accessibilité, modéré sur les durées exactes (conventions convergentes plus qu'une vérité unique).

Échelle de preuve: [solide] standard ou résultat répliqué, [modéré] études et conventions convergentes, [fragile] effet faible ou contextuel.

## Résumé

Le mouvement utile fait trois choses: assurer la continuité entre deux états, confirmer une action par un retour immédiat, et signaler une attente. Le reste est décor et nuit. Les durées efficaces sont courtes, de l'ordre de 100 à 300 ms, et presque jamais au-delà de 500 ms pour une interaction. Le mouvement attire l'œil de force, donc il faut le réserver à ce qui compte. L'accessibilité impose de respecter `prefers-reduced-motion`. Et l'excès d'animation est justement ce qui fait « produit IA ». Pour un outil calme, l'interface doit très peu bouger.

## 1. À quoi sert vraiment une animation

L'animation aide rarement la compréhension d'un contenu [solide]. Tversky, Morrison et Bétrancourt (2002) montrent qu'une animation est souvent trop rapide ou trop complexe pour être perçue correctement, et qu'on ne peut pas la ré-inspecter à son rythme comme une image fixe. Elle n'aide que si elle respecte deux principes: la congruence (le mouvement correspond au changement réel) et l'appréhension (elle reste assez lente et simple pour être suivie). Son usage le plus solide est de réorienter dans le temps et l'espace, pas de décorer.

En pratique d'interface, le mouvement utile est fonctionnel: il relie deux états (d'où vient cet écran), il confirme une cause (j'ai cliqué, il se passe quelque chose), il dirige le regard, ou il signale une attente [modéré, consensus de praticiens, Val Head].

Enfin, le mouvement est préattentif [solide]: l'œil le capte en moins de 250 ms, avant toute lecture (Ware). C'est puissant et involontaire, donc à réserver. Dans une interface calme, faire bouger un élément revient à pointer dessus du doigt.

## 2. Durées et courbes

Trois limites de temps de réponse cadrent tout [solide] (Miller 1968, repris par Nielsen): 0.1 s donne la sensation d'instantané, 1 s garde le fil de la pensée, 10 s est la limite d'attention. Le modèle RAIL de Google et le seuil de Doherty précisent: répondre visuellement en moins de 100 ms, et rester sous environ 400 ms pour garder l'engagement [modéré].

Les durées d'animation qui reviennent dans les guides convergent [modéré]:
- micro-retour (bouton, bascule): 100 à 200 ms, une bascule sous 200 ms;
- transition entre états ou vues: 200 à 300 ms;
- apparition d'un élément plus grand: jusqu'à environ 400 ms;
- Apple recommande une fourchette de 100 à 500 ms; Material distingue durées courtes pour les petits éléments et plus longues pour les grands.

Au-delà de 500 ms, une animation liée à une interaction est ressentie comme lente.

Pour les courbes: une sortie douce (départ rapide, arrivée amortie) convient aux apparitions; un amorti des deux côtés convient à un déplacement entre deux positions; le linéaire est réservé aux indicateurs indéterminés. Le rebond et l'élastique sont à éviter: ils se lisent comme un effet marketing, pas comme un outil système.

## 3. Coûts et accessibilité

L'excès d'animation coûte cher [modéré]: bruit visuel, charge cognitive, et lenteur perçue quand chaque action est ralentie par une transition.

Le mal des transports visuel est réel et concerne aussi les écrans plats [solide]. La théorie dominante est le conflit sensoriel: l'œil voit du mouvement que l'oreille interne ne ressent pas. Les déclencheurs les plus cités sont la parallaxe, les zooms, les fonds qui défilent et les éléments qui tournent, surtout en périphérie du regard. La sensibilité varie fortement d'une personne à l'autre.

Côté norme [solide]:
- WCAG 2.2.2 (niveau A) impose un moyen de mettre en pause, arrêter ou masquer tout mouvement automatique non essentiel;
- WCAG 2.3.3 (niveau AAA) demande de pouvoir désactiver les animations déclenchées par une interaction;
- il faut respecter la requête `prefers-reduced-motion` et réduire le mouvement à presque rien;
- les indicateurs de chargement sont considérés comme essentiels et restent autorisés;
- la dégradation doit être propre: couper le mouvement ne doit jamais casser l'accès.

BeSecured respecte déjà `prefers-reduced-motion`. Une option de réglage dans l'interface serait un plus.

## 4. L'attente et la performance perçue

Tout indicateur vaut mieux qu'un écran vide [solide]. Mais la perception du temps ne suit pas le temps réel [modéré]. Quelques résultats utiles:
- les dernières fractions d'une barre pèsent le plus dans le souvenir de l'attente;
- une animation peut faire paraître une barre plus rapide; Harrison et al. mesurent qu'un motif qui recule dans la barre la fait percevoir environ 11 % plus courte;
- une vitesse constante ou qui accélère vers la fin est perçue comme plus rapide;
- ces effets s'expliquent par l'illusion de durée remplie et la loi de Weber, et ils sont plus sensibles sur les attentes courtes.

Écran squelette ou indicateur tournant: le squelette est un peu meilleur pour les chargements lourds et longs, l'indicateur tournant suffit pour une action courte; l'effet reste modeste.

Conséquence pour BeSecured: le scan ne fournit pas de progression réelle étape par étape. Le bon choix est donc un état indéterminé honnête, déjà en place, sans simuler une fausse progression détaillée. C'est cohérent avec la ligne d'honnêteté de l'outil, où un contrôle non disponible est marqué comme tel.

## 5. Pourquoi « trop animé » fait IA

L'excès d'animation est un marqueur de la moyenne produite par l'IA [modéré]. Quand la consigne est vague, les outils génératifs ajoutent des effets spectaculaires par défaut: entrées orchestrées au chargement, survols animés partout, pulsations en boucle, confetti. Ce sont les mêmes signes que la « moyenne SaaS » repérée dans la note précédente.

La parade est la même: un mouvement minimal et fonctionnel. Un vrai utilitaire système bouge peu, et c'est précisément ce qui le rend crédible.

## 6. Directives concrètes pour BeSecured

Animer seulement:
- la transition entre vues (fondu court ou léger déplacement);
- l'apparition du score, une seule fois, à l'arrivée des résultats;
- l'état de scan, en indéterminé;
- le retour des boutons et des bascules.

Durées:
- retours et bascules: 120 à 200 ms;
- transition de vue: 200 à 280 ms;
- révélation du score: 400 à 500 ms (l'anneau actuel est à 700 ms, il peut descendre vers 500);
- jamais au-delà de 500 ms pour une interaction.

Courbes: sortie douce pour les apparitions, amorti pour les déplacements, pas de rebond ni d'élastique. Linéaire uniquement pour le balayage indéterminé du scan.

Interdits: parallaxe, fond animé, pulsations en boucle, confetti, orchestration d'entrée au chargement, survols animés sur chaque élément. Ils nuisent à la lecture, fatiguent, et font « produit IA ».

Accessibilité: continuer à respecter `prefers-reduced-motion` en réduisant à quasi nul, garder l'indicateur de scan, et prévoir si possible une option de désactivation.

Règle d'or: si une animation n'aide pas à comprendre un changement, l'enlever.

## 7. Brief animations pour Claude Design

```
Pour BeSecured, un utilitaire de diagnostic de sécurité local et calme, le mouvement
doit être rare et fonctionnel. Il sert seulement à trois choses: relier deux états,
confirmer une action, signaler une attente. Tout le reste est du décor à supprimer.

Ce qu'on anime, et rien d'autre:
- transition entre vues: fondu court ou léger déplacement, 200 à 280 ms;
- retour d'un bouton ou d'une bascule: 120 à 200 ms (bascule sous 200 ms);
- apparition du score à l'arrivée des résultats: une seule fois, 400 à 500 ms;
- état de scan: un indicateur indéterminé (balayage linéaire), sans fausse
  progression détaillée, puisque le scan ne donne pas d'étapes réelles.

Courbes: sortie douce (départ rapide, arrivée amortie) pour les apparitions, amorti
des deux côtés pour un déplacement. Pas de rebond, pas d'élastique.

Interdits, car ils nuisent à la lecture et font « produit IA »: parallaxe, fond animé,
pulsations en boucle, confetti, entrées orchestrées au chargement, survols animés
partout, et toute animation au-delà de 500 ms sur une interaction.

Accessibilité obligatoire: respecter prefers-reduced-motion en réduisant le mouvement
à presque rien, tout en gardant l'indicateur de scan. Une option pour couper les
animations est bienvenue.

Règle d'or: si une animation n'aide pas à comprendre un changement à l'écran, la
retirer. Un vrai logiciel système bouge peu.
```

## Sources

1. Tversky, B., Morrison, J. B., et Bétrancourt, M. (2002). Animation: Can it facilitate? International Journal of Human-Computer Studies, 57, 247-262. https://doi.org/10.1006/ijhc.2002.1017
2. Nielsen, J. Response Times: The 3 Important Limits (d'après Miller, 1968). Nielsen Norman Group. https://www.nngroup.com/articles/response-times-3-important-limits/
3. Google, RAIL model (Irish et Lewis, 2015). web.dev. https://web.dev/articles/rail
4. Doherty, W. J., et Thadani, A. J. (1982). The economic value of rapid response time. IBM (seuil de Doherty).
5. Material Design 3, Motion: durations et easing. https://m3.material.io/styles/motion/overview
6. Apple, Human Interface Guidelines, Motion. https://developer.apple.com/design/human-interface-guidelines/motion
7. Head, V. Designing Interface Animation et l'animation fonctionnelle. A List Apart, Rosenfeld Media.
8. Ware, C. Information Visualization: Perception for Design (le mouvement comme attribut préattentif).
9. WCAG 2.1, Understanding SC 2.2.2 Pause, Stop, Hide. https://www.w3.org/WAI/WCAG21/Understanding/pause-stop-hide.html
10. WCAG 2.1, Understanding SC 2.3.3 Animation from Interactions. https://www.w3.org/WAI/WCAG21/Understanding/animation-from-interactions.html
11. MDN, prefers-reduced-motion. https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion
12. Head, V. Designing Safe(r) Web Animation For Motion Sensitivity. A List Apart. https://alistapart.com/article/designing-safer-web-animation-for-motion-sensitivity/
13. Harrison, C., et al. (2007). Rethinking the Progress Bar. UIST; et Faster Progress Bars (2010).
14. Nielsen Norman Group, Progress Indicators et écrans squelette. https://www.nngroup.com/articles/progress-indicators/
15. Sensory conflict theory et mal des transports visuel induit par les écrans; questionnaire VIMSSQ (Keshavarz et Golding).
16. Liang, C., et al. (2026). Beyond Screenshots: Evaluating VLMs' Understanding of UI Animations. arXiv:2604.26148. https://arxiv.org/abs/2604.26148
17. Shin, D., et al. (2026). Interrogating Design Homogenization in Web Vibe Coding. arXiv:2603.13036. https://arxiv.org/abs/2603.13036

## Limites

Les durées exactes sont des conventions convergentes, pas une loi: à ajuster au ressenti. Une partie de la recherche sur le mal des transports visuel vient de la réalité virtuelle, transférable avec prudence à une interface plate, mais le principe du conflit sensoriel reste valable. La recherche a été menée par recherche web et arXiv, sans firecrawl ni exa; certaines sources ont été lues via résumé. Les recommandations rejoignent et précisent ce qui existe déjà dans BeSecured: respect de `prefers-reduced-motion` et état de scan indéterminé honnête.
