# Amarita — déploiement

## Fichiers
- `amarita-backend.js` : serveur Express + API + MongoDB
- `index.html` : boutique/client
- `livreur.html` : portail livreur indépendant
- `conditions.html` : conditions d'utilisation
- `confidentialite.html` : politique de confidentialité
- `package.json` : dépendances et démarrage
- `.env.example` : variables d'environnement à renseigner

## Render
1. Déployer le dossier dans un service Node/Render.
2. Commande : `npm install` puis démarrage : `npm start`.
3. Renseigner toutes les variables de `.env.example` dans Render → Environment.
4. En production, `JWT_SECRET` et `AMARITA_ADMIN_KEY` doivent avoir au moins 32 caractères.
5. `BASE_URL` doit correspondre exactement au domaine public HTTPS.
6. Si PayTech est activé en production, utiliser les clés validées par PayTech et `PAYTECH_ENV=prod` selon la configuration du compte.

## Parcours livraison
Commande avec livraison → commande enregistrée → paiement confirmé → course `a_attribuer` → livreur indépendant actif/disponible → acceptation → récupération → en livraison + GPS → livrée → avis client.

## Portail livreur
- `/livreur` et `/livreur.html` ouvrent le portail.
- L'activation d'un compte livreur se fait par l'API d'administration avec `X-Amarita-Admin-Key`.
- Ne jamais mettre `AMARITA_ADMIN_KEY`, `JWT_SECRET`, les clés MongoDB, PayTech ou Anthropic dans le frontend.

## Avant ouverture commerciale
- Remplacer les mentions `[À COMPLÉTER]` de `confidentialite.html` par l'identité juridique réelle de l'exploitant, son adresse et les contacts légaux.
- Faire valider les textes juridiques selon le droit applicable au Sénégal.
- Configurer et tester MongoDB Atlas, PayTech/IPN et, si utilisé, Anthropic.
- Tester une commande réelle en environnement de paiement approprié avant d'activer la production.
