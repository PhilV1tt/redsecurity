# Interface et couleurs de BeSecured: note de recherche

Document destiné à briefer Claude Design. Objectif: fonder les choix d'interface et de couleurs sur des preuves, pas sur des goûts, pour un outil de diagnostic de sécurité local, utilisé par des personnes non techniques, en français, en mode clair.

Sources principales: standards W3C, études HCI, science de la couleur, littérature « usable security », et preprints arXiv récents. Niveau de confiance global: élevé sur l'accessibilité et la sécurité utilisable, faible sur la psychologie des couleurs (voir section 3).

Échelle de preuve utilisée: [solide] standard ou résultat répliqué, [modéré] études convergentes, [fragile] effets faibles, contextuels ou peu répliqués.

## Résumé

Quatre choses sont bien établies. Une interface se juge en une fraction de seconde, et ce premier jugement nourrit la crédibilité. Le contraste et le fait de ne jamais coder une information par la seule couleur sont des règles d'accessibilité fermes. En sécurité, les avertissements échouent surtout par habituation, jargon et peur, pas par manque de couleur. Et les interfaces produites par l'IA se ressemblent parce que les modèles convergent vers une moyenne sûre quand la consigne est vague.

Une chose est fragile: la psychologie des couleurs. « Rouge égale danger, bleu égale confiance » correspond à des effets réels mais faibles, dépendants du contexte et de la culture. Il ne faut pas attendre d'une teinte qu'elle crée de la confiance.

La conséquence pour BeSecured: garder une palette sobre et accessible, utiliser la couleur pour sa fonction conventionnelle apprise (niveaux de gravité, comme un feu tricolore) et non pour induire une émotion, et donner à Claude Design des contraintes précises plutôt qu'une consigne ouverte.

## 1. Première impression et confiance

Un internaute forme un jugement de valeur visuelle d'une page en environ 50 ms, et ce jugement est très corrélé à celui formé après un temps plus long [modéré] (Lindgaard et al., 2006). Le programme de recherche sur la crédibilité de Stanford montre que, pour la plupart des gens, la qualité visuelle et la mise en page pèsent lourd dans le jugement de crédibilité d'un site [solide] (Fogg et al., CHI 2003; Stanford Web Credibility Guidelines).

Nuance importante: le poids de l'esthétique baisse quand la décision est complexe ou quand l'utilisateur est expert; là, c'est le contenu qui décide [modéré]. La confiance initiale et la confiance durable ne se gagnent pas pareil: la première vient vite du visuel, la seconde vient de la clarté et de la tenue du contenu.

Pour BeSecured: l'outil doit paraître crédible tout de suite, car un non-expert doit croire le diagnostic sans pouvoir le vérifier. Mais la confiance qui dure vient de la lisibilité des constats et de la transparence (« rien n'est envoyé »), pas du vernis graphique.

## 2. La couleur: ce qui est établi

**Contraste [solide].** WCAG demande un ratio d'au moins 4.5:1 pour le texte courant, 3:1 pour le grand texte (à partir d'environ 24 px, ou 18.66 px en gras), et 3:1 pour les éléments non textuels utiles comme les icônes, les bordures de champ et les traits de graphique (WCAG 1.4.3 et 1.4.11). Le niveau AAA monte à 7:1. La palette actuelle de BeSecured passe déjà AA pour le texte sur fond blanc (ratios calculés en section 7), donc le contraste n'est pas le problème à régler.

**Ne pas coder une information par la seule couleur [solide].** WCAG 1.4.1 interdit de s'appuyer uniquement sur la couleur pour transmettre un sens. Les échecs classiques: une erreur affichée seulement en rouge, un lien distingué du texte par la seule couleur, un statut « vert égale ok, rouge égale échec » sans autre marque. La parade: doubler toujours la couleur par une icône, une forme, un libellé ou un ordre.

**Daltonisme [solide].** Environ 8 % des hommes et 0.5 % des femmes d'origine nord-européenne ont une déficience de la vision des couleurs, surtout une confusion rouge-vert (deutéranopie, protanopie). Donc le rouge « critique » et le vert « conforme » ne doivent jamais se distinguer par la seule teinte.

**Palettes sûres [solide à modéré].** La palette d'Okabe et Ito (huit couleurs choisies pour rester distinctes en vision déficiente, avec une large plage de luminance) est une référence; ColorBrewer propose des jeux marqués « CVD-safe ». Pour les échelles continues, éviter l'arc-en-ciel et le jet, préférer une luminance monotone et perceptuellement uniforme type viridis (Kovesi, 2015).

Précision tirée du calcul de contraste: les couleurs vives d'Okabe-Ito conviennent comme aplats ou pastilles, mais pas comme texte coloré sur blanc (l'orange tombe à 2.25:1, le bleu ciel à 2.31:1). Il faut donc réserver les teintes vives aux remplissages et assombrir pour le texte.

## 3. La couleur: ce qui est fragile

L'idée qu'une couleur porte une émotion stable (rouge égale danger, bleu égale confiance, vert égale sûr) est surévaluée [fragile]. La théorie de la couleur en contexte (Elliot et Maier) soutient que le sens d'une couleur dépend du contexte où elle apparaît. La revue d'Elliot (2015) le dit franchement: le domaine est jeune, les effets sont souvent petits et conditionnels, et il faut rester prudent sur les applications réelles. La théorie de la valence écologique (Palmer et Schloss) explique les préférences de couleur par l'association aux objets agréables ou non, pas par un câblage fixe. Les travaux sur couleur et confiance (par exemple « Trustworthy Blue or Untrustworthy Red ») vont dans le même sens: des effets existent mais restent modestes et sensibles au contexte.

Conséquence pratique: ne pas demander à une couleur de « créer » de la confiance. Utiliser la couleur pour sa fonction conventionnelle et apprise. Le rouge, l'orange et le vert marchent comme niveaux de gravité parce que la convention du feu tricolore est partagée, pas parce que la teinte est intrinsèquement chargée. Le bleu « système » d'un outil de sécurité est un choix de convention, repris des systèmes d'exploitation et des antivirus, à assumer comme tel.

## 4. Montrer un score et des points à corriger pour des non-experts

**Jauges [modéré].** Les cadrans de type jauge sont critiqués en visualisation de données (Stephen Few): ils occupent beaucoup de place pour une seule valeur et ne montrent pas de tendance. Un grand nombre lisible avec son libellé, ou un bullet graph, transmet la même chose plus vite. Pour un verdict unique comme « 92 sur 100 », un grand chiffre, un grade et une phrase valent mieux qu'un cadran décoratif. Un anneau de score reste acceptable s'il est sobre et secondaire.

**Attributs préattentifs [solide].** La couleur, la position et la taille sont traitées par l'œil en moins de 250 ms (Ware; NN/g). Il faut donc réserver la couleur saturée aux éléments qui doivent ressortir, le critique d'abord, et garder le reste neutre. Une interface où tout est coloré ne hiérarchise plus rien.

**Redondance de la gravité [solide].** Coder chaque niveau par couleur, plus icône, plus libellé, plus ordre d'affichage (le critique en premier). C'est l'application directe de la règle 1.4.1 et c'est ce qui rend l'interface lisible pour un daltonien.

## 5. Spécifique à la sécurité

**Les avertissements échouent souvent [solide].** Les vieux designs étaient ignorés dans 50 à 80 % des cas (Egelman, Cranor et Hong, CHI 2008; Sunshine et Cranor, « Crying Wolf », USENIX 2009). Les causes: habituation, jargon, manque d'attention. Les bons designs récents font beaucoup mieux, autour de 75 à 90 % d'efficacité (Akhawe et Felt, « Alice in Warningland », USENIX 2013).

**Principes [solide à modéré].** Réduire l'encombrement, un mot-signal clair, énoncer le danger en clair, cacher les détails techniques, proposer un choix par défaut net, et expliquer plutôt qu'effrayer (Sasse, 2015). Le modèle C-HIP décrit la chaîne à réussir: remarquer, comprendre, croire, être motivé, agir. Un avertissement échoue dès qu'un maillon casse.

**Confiance par la transparence.** Pour un outil local, le message « aucun compte, rien n'est envoyé, tout reste sur la machine » est un signal de confiance fort, à rendre visible. La forme « constat, pourquoi c'est important, étapes pour corriger », sans jargon, correspond à l'approche par modèles mentaux de Bravo-Lillo et Cranor.

## 6. Pourquoi les interfaces IA se ressemblent, et comment l'éviter

**Cause [modéré, littérature récente].** Les modèles sont entraînés sur des données dominées par quelques conventions et convergent vers une moyenne sûre, surtout quand la consigne est vague. Des travaux récents le montrent sur le code et le design web généré (Shin et al., « Interrogating Design Homogenization in Web Vibe Coding », arXiv 2603.13036, 2026) et plus largement sur la diversité collective qui chute quand on génère sans contrainte (Doshi et Hauser, 2024; Raghavan, arXiv 2412.08610, 2024).

**Signes de cette moyenne.** Petit intitulé en majuscules au-dessus des titres, dégradés, grand titre marketing, pastilles et badges colorés partout, tableaux zébrés, phrases motivantes, emoji. C'est exactement ce qui fait « produit IA » et ce qu'il faut éviter ici.

**Comment l'éviter [directive].** Ancrer la conception dans le sujet réel: un utilitaire de diagnostic système, pas un produit SaaS. Prendre comme référence de vrais logiciels système (les Réglages de macOS, un antivirus comme Malwarebytes) plutôt qu'un tableau de bord générique. Restreindre: une seule couleur d'accent, peu de couleurs, typographie système, pas de décor. Donner à Claude Design des contraintes précises et un parti pris, ce que la littérature appelle une friction productive (Shin et al., 2026): sans cela, il régresse vers la moyenne. Et assumer le pari de la sobriété crédible, un outil « ennuyeux dans le bon sens » qui passe pour un vrai logiciel.

## 7. Directives concrètes pour BeSecured

Palette proposée, avec ratios de contraste calculés sur fond blanc (cible: 4.5:1 pour le texte, 3:1 pour icônes et traits).

Surfaces et texte:
- Fond fenêtre `#e9ebee`, rail `#f4f5f7`, contenu `#ffffff`, lignes `#d9dde3`.
- Texte principal `#15181d` (17.8:1), texte atténué `#5d6571` (5.9:1).

Accent unique, par convention système, usage parcimonieux:
- Bleu `#2b5bb5` (6.4:1).

Gravité, toujours couleur plus icône plus libellé plus ordre:
- Critique `#b3261e` (6.5:1), avertissement `#8a5a00` (5.9:1), conforme `#1f7a3d` (5.4:1), info `#1d63a8` (6.2:1), ignoré `#5d6571` (5.9:1).
- Pour des pastilles pleines, des teintes plus vives type Okabe-Ito sont acceptables, puisque l'information n'est jamais portée par la seule couleur.

Le reste:
- Typographie: pile système (San Francisco sur Mac, Segoe UI sur Windows), chiffres en chasse fixe pour les scores. Pas de police d'affichage gadget.
- Structure: rail de sections plus panneau de contenu, un seul appel à l'action, le verdict en haut, les points classés par gravité, la rassurance vie privée visible. Pas d'intitulé en majuscules, pas de grand titre marketing.
- Score: un grand chiffre lisible avec grade et une phrase; anneau sobre toléré, jamais central ni décoratif.
- Mouvement: discret, et respecter `prefers-reduced-motion`.
- Accessibilité: viser AA partout, ne jamais coder par la seule couleur, tester en simulation daltonien.

## 8. Brief prêt à coller pour Claude Design

```
Je conçois l'interface de BeSecured, un outil de diagnostic de sécurité 100% local
pour des particuliers non techniques, francophones, en mode clair. Ce n'est pas une
application web hébergée: un petit serveur local sert l'interface, qui s'ouvre dans
une fenêtre dédiée sans barre d'adresse. Rien ne quitte la machine.

Direction: un utilitaire de diagnostic système, calme et crédible, dans l'esprit des
Réglages de macOS ou d'un antivirus comme Malwarebytes. À éviter absolument, la
moyenne « produit IA »: pas d'intitulé en majuscules au-dessus des titres, pas de
dégradés, pas de grand titre marketing, pas de pastilles colorées partout, pas de
tableaux zébrés, pas d'emoji.

Règles fondées sur la recherche, à respecter:
- Tout passe AA: texte >= 4.5:1, icônes et traits >= 3:1.
- Ne jamais coder une information par la seule couleur: la gravité se lit aussi par
  une icône, un libellé et l'ordre (le critique en premier). 8% des hommes confondent
  le rouge et le vert.
- Une seule couleur d'accent (bleu système), employée avec parcimonie. La couleur
  saturée est réservée à ce qui doit ressortir.
- Pas de jauge décorative pour le score: un grand chiffre, un grade, une phrase.
- Transparence vie privée visible (aucun compte, rien n'est envoyé), sans jargon.

Palette de départ (fond blanc):
- surfaces #e9ebee / #f4f5f7 / #ffffff, lignes #d9dde3
- texte #15181d, atténué #5d6571
- accent #2b5bb5
- gravité: critique #b3261e, avertissement #8a5a00, conforme #1f7a3d, info #1d63a8,
  ignoré #5d6571

Écrans à couvrir: accueil (un bouton pour lancer le scan, la liste des contrôles),
scan en cours (état honnête, sans fausse progression), aperçu (score sur 100, grade,
répartition par statut), catégories (tableau), points à corriger (constats par
gravité, chacun avec constat, pourquoi c'est important, étapes), rapport (export HTML).

Livrables: une direction visuelle précise (palette, typographie, grille), un élément
signature sobre, une maquette par écran, et pour chaque choix une phrase qui dit
pourquoi il colle à un outil de sécurité local plutôt qu'à un produit IA. Prends le
risque de la sobriété crédible: la réussite, c'est que ça passe pour un vrai logiciel
système.
```

## Sources

1. WCAG 2.1, Understanding SC 1.4.3 Contrast (Minimum). https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html
2. WCAG 2.1, Understanding SC 1.4.1 Use of Color. https://www.w3.org/WAI/WCAG21/Understanding/use-of-color.html
3. WCAG 2.1, Understanding SC 1.4.11 Non-text Contrast. https://www.w3.org/WAI/WCAG21/Understanding/non-text-contrast.html
4. Okabe et Ito, Color Universal Design (palette sûre). https://jfly.uni-koeln.de/color/
5. Wong, B. (2011). Points of view: Color blindness. Nature Methods. https://www.nature.com/articles/nmeth.1618
6. Kovesi, P. (2015). Good Colour Maps: How to Design Them. arXiv:1509.03700. https://arxiv.org/abs/1509.03700
7. Elliot, A. J. (2015). Color and psychological functioning: a review of theoretical and empirical work. Frontiers in Psychology. https://www.frontiersin.org/articles/10.3389/fpsyg.2015.00368/full
8. Elliot, A. J., et Maier, M. A. Color-in-Context Theory (Advances in Experimental Social Psychology, 2012).
9. Palmer, S. E., et Schloss, K. B. (2010). An ecological valence theory of human color preference. PNAS.
10. Fogg, B. J., et al. (2003). How do users evaluate the credibility of Web sites? CHI 2003; Stanford Web Credibility Guidelines. https://credibility.stanford.edu/guidelines/index.html
11. Lindgaard, G., et al. (2006). Attention web designers: You have 50 milliseconds to make a good first impression! Behaviour & Information Technology. https://doi.org/10.1080/01449290500330448
12. Few, S. Bullet graphs et critique des jauges. Perceptual Edge. https://www.perceptualedge.com/
13. Nielsen Norman Group, Using Preattentive Attributes in Dashboards. https://www.nngroup.com/articles/dashboards-preattentive/
14. Nielsen Norman Group, Trustworthiness in Web Design. https://www.nngroup.com/articles/trustworthy-design/
15. Egelman, S., Cranor, L. F., et Hong, J. (2008). You've Been Warned. CHI 2008.
16. Sunshine, J., Egelman, S., Almuhimedi, H., Atri, N., et Cranor, L. F. (2009). Crying Wolf: An Empirical Study of SSL Warning Effectiveness. USENIX Security. https://www.usenix.org/legacy/event/sec09/tech/full_papers/sunshine.pdf
17. Akhawe, D., et Felt, A. P. (2013). Alice in Warningland. USENIX Security.
18. Bravo-Lillo, C., Cranor, L. F., et al. Attractors et modèles mentaux des avertissements (SOUPS).
19. Revisiting the Design Agenda for Privacy Notices and Security Warnings. arXiv:2304.08780. https://arxiv.org/abs/2304.08780
20. Sasse, M. A. (2015). Scaring and Bullying People into Security Won't Work. IEEE Security & Privacy.
21. Shin, D., et al. (2026). Interrogating Design Homogenization in Web Vibe Coding. arXiv:2603.13036. https://arxiv.org/abs/2603.13036
22. Doshi, A. R., et Hauser, O. P. (2024). Generative AI enhances individual creativity but reduces the collective diversity of novel content. Science Advances.
23. Raghavan, M. (2024). Competition and Diversity in Generative AI. arXiv:2412.08610. https://arxiv.org/abs/2412.08610
24. Nielsen Norman Group, Dark Mode vs. Light Mode (polarité positive et lisibilité). https://www.nngroup.com/articles/dark-mode/

## Limites

La psychologie des couleurs est le maillon faible: ne pas en faire un argument de vente. Une partie de la recherche sur la crédibilité et l'esthétique porte sur des sites web grand public, transférable avec prudence à un utilitaire local. Recherche menée par recherche web et arXiv, sans accès aux moteurs firecrawl ou exa; quelques sources ont été lues via résumé plutôt qu'en texte intégral. Les ratios de contraste de la section 7 sont calculés (formule WCAG, fond blanc) et reproductibles.
