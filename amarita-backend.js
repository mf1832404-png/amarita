/**
 * Serveur unique pour Amarita — site + backend + vraie base de données
 * -----------------------------------------------------------------------
 * Un seul serveur qui :
 *   1. Affiche le site (index.html) à l'adresse principale
 *   2. Gère les comptes vendeurs (inscription / connexion par e-mail,
 *      ou connexion avec Apple)
 *   3. Gère l'ajout, la liste et la suppression de produits par les vendeurs
 *   4. Enregistre chaque commande et calcule la commission Amarita (10%)
 *      et la part due à chaque vendeur (90%)
 *   5. Paiement par Wave et Orange Money (liens/instructions simples, gérés
 *      côté site — aucune clé API requise pour ces deux-là)
 *
 * Les données (vendeurs, produits, commandes) sont stockées dans
 * MongoDB Atlas, gratuit et persistant.
 *
 * Installation :
 *   npm install
 *   MONGODB_URI=... JWT_SECRET=... APPLE_CLIENT_ID=... ANTHROPIC_API_KEY=... npm start
 *
 * (nécessite Node.js 18 ou plus récent, pour que "fetch" soit disponible nativement)
 *
 * APPLE_CLIENT_ID : l'identifiant "Services ID" créé dans votre compte
 * Apple Developer (ex: com.amarita.web), avec "Sign in with Apple" activé
 * pour votre domaine Render. Sans ce compte configuré côté Apple, le
 * bouton "Se connecter avec Apple" ne pourra pas fonctionner encore.
 *
 * MONGODB_URI : à récupérer sur mongodb.com/cloud/atlas — ne jamais
 * l'écrire en clair dans le code, toujours via une variable
 * d'environnement (sur Render : Environment → MONGODB_URI).
 *
 * Fichiers attendus dans le même dossier que ce script :
 *   - index.html   (le site)
 *   - package.json (déjà fourni, avec les dépendances incluses)
 */

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
const appleSignin = require('apple-signin-auth');

const app = express();
app.use(express.json({ limit: '6mb' })); // les photos de produits arrivent en base64 dans le JSON

// Sert index.html (et tout autre fichier posé dans ce même dossier)
// directement à la racine du site.
app.use(express.static(__dirname, { index: 'index.html' }));

const JWT_SECRET = process.env.JWT_SECRET || "change-moi-absolument-avant-de-publier";
// .trim() est important : coller une variable d'environnement depuis un
// clavier de téléphone laisse parfois un espace ou un retour à la ligne
// invisible au début/à la fin, ce qui suffit à faire échouer l'authentification
// MongoDB sans que rien ne paraisse anormal à l'œil.
const MONGODB_URI = (process.env.MONGODB_URI || "").trim();
// "Services ID" créé dans le compte Apple Developer (Certificates, Identifiers & Profiles
// → Identifiers → +  → Services IDs), avec "Sign in with Apple" activé pour ce domaine.
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID || "com.amarita.web";
// Commission Amarita prélevée sur chaque commande : 10% pour la plateforme, 90% pour le vendeur.
const COMMISSION_RATE = 0.10;
// Clé API Anthropic pour l'assistant shopping IA — à créer sur console.anthropic.com
// (Get API Key), puis à coller dans Render → Environment → ANTHROPIC_API_KEY.
// Facturée à l'usage par Anthropic (pas par Amarita/Render) ; modèle Haiku
// utilisé ici pour rester très peu coûteux.
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";

if (!MONGODB_URI) {
  console.error("⚠️  MONGODB_URI n'est pas définie. Ajoutez-la dans les variables d'environnement (voir les instructions).");
} else {
  // Affiche uniquement le nom d'utilisateur détecté dans la chaîne de connexion
  // (jamais le mot de passe) — utile pour repérer une faute de frappe dans les
  // logs Render sans exposer d'information sensible.
  const userMatch = MONGODB_URI.match(/\/\/([^:]+):/);
  console.log(`MongoDB : nom d'utilisateur détecté dans MONGODB_URI = "${userMatch ? userMatch[1] : '(non détecté — vérifiez le format de la chaîne)'}"`);
}

// ---------- Authentification ----------
function authMiddleware(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Connexion requise." });
  try {
    req.seller = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session invalide, reconnectez-vous." });
  }
}

// Le cluster MongoDB Atlas gratuit (M0) se met en pause après inactivité et
// met quelques secondes à se "réveiller". Sans ça, la toute première tentative
// de connexion après une pause échoue et fait planter le serveur inutilement
// (Render le relance alors tout seul, ce qui ressemble à un déploiement raté).
// On réessaie donc plusieurs fois avant d'abandonner pour de bon.
async function connectWithRetry(uri, attempts = 5, delayMs = 4000){
  for (let i = 1; i <= attempts; i++){
    try {
      const client = new MongoClient(uri);
      await client.connect();
      return client;
    } catch (err) {
      console.error(`Connexion MongoDB : tentative ${i}/${attempts} échouée — ${err.message}`);
      if (i === attempts) throw err;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

async function start(){
  const client = await connectWithRetry(MONGODB_URI);
  const db = client.db('Amarita');
  const sellers = db.collection('sellers');
  const products = db.collection('products');
  const orders = db.collection('orders');

  // Une même adresse e-mail ne peut créer qu'un seul compte vendeur
  // (que ce soit par mot de passe ou par Apple).
  await sellers.createIndex({ email: 1 }, { unique: true });

  app.get('/api/health', (req, res) => {
    res.send('✅ Serveur Amarita en ligne — site, comptes vendeurs, commandes et assistant IA actifs (base de données connectée).');
  });

  // ---------- Comptes vendeurs ----------
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  app.post('/api/auth/signup', async (req, res) => {
    try {
      const { name, email, password } = req.body;
      if (!name || !email || !password) {
        return res.status(400).json({ error: "Nom, e-mail et mot de passe requis." });
      }
      if (!EMAIL_RE.test(email)) {
        return res.status(400).json({ error: "Adresse e-mail invalide." });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: "Le mot de passe doit faire au moins 6 caractères." });
      }
      const existing = await sellers.findOne({ email });
      if (existing) {
        return res.status(400).json({ error: "Un compte existe déjà avec cet e-mail." });
      }
      const seller = {
        id: "s_" + Date.now(),
        name,
        email,
        authProvider: 'local',
        passwordHash: bcrypt.hashSync(password, 10),
        createdAt: new Date().toISOString()
      };
      await sellers.insertOne(seller);
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '90d' });
      res.json({ token, seller: { id: seller.id, name: seller.name } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      const seller = await sellers.findOne({ email });
      if (!seller || seller.authProvider === 'apple' || !bcrypt.compareSync(password || '', seller.passwordHash || '')) {
        return res.status(401).json({ error: "E-mail ou mot de passe incorrect." });
      }
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '90d' });
      res.json({ token, seller: { id: seller.id, name: seller.name } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la connexion." });
    }
  });

  // Connexion / inscription automatique via "Se connecter avec Apple".
  // Le frontend envoie le id_token reçu d'Apple ; on le vérifie ici
  // auprès d'Apple avant de faire confiance à l'e-mail qu'il contient.
  app.post('/api/auth/apple', async (req, res) => {
    try {
      const { id_token, name } = req.body;
      if (!id_token) {
        return res.status(400).json({ error: "Jeton Apple manquant." });
      }
      let applePayload;
      try {
        applePayload = await appleSignin.verifyIdToken(id_token, {
          audience: APPLE_CLIENT_ID,
          ignoreExpiration: false
        });
      } catch (e) {
        console.error("Vérification Apple échouée :", e.message);
        return res.status(401).json({ error: "Connexion Apple invalide ou expirée." });
      }
      const email = applePayload.email;
      if (!email) {
        return res.status(400).json({ error: "Apple n'a pas transmis d'e-mail pour ce compte." });
      }
      let seller = await sellers.findOne({ email });
      if (!seller) {
        seller = {
          id: "s_" + Date.now(),
          name: name || email.split('@')[0],
          email,
          authProvider: 'apple',
          appleSub: applePayload.sub,
          passwordHash: null,
          createdAt: new Date().toISOString()
        };
        await sellers.insertOne(seller);
      }
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '90d' });
      res.json({ token, seller: { id: seller.id, name: seller.name } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la connexion Apple." });
    }
  });

  // ---------- Produits ----------
  app.get('/api/products', async (req, res) => {
    try {
      const list = await products.find({}, { projection: { _id: 0 } }).toArray();
      res.json({ products: list });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors du chargement des produits." });
    }
  });

  app.post('/api/products', authMiddleware, async (req, res) => {
    try {
      const { name, price, cat, icon, image } = req.body;
      const allowedCats = ["mode", "beaute", "epicerie", "artisanat"];
      if (!name || !price || !allowedCats.includes(cat)) {
        return res.status(400).json({ error: "Nom, prix et catégorie valide requis." });
      }
      if (image && !image.startsWith('data:image/')) {
        return res.status(400).json({ error: "Format de photo invalide." });
      }
      const product = {
        id: "p_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
        sellerId: req.seller.id,
        sellerName: req.seller.name,
        name,
        price: Number(price),
        cat,
        icon: icon || "🛍️",
        image: image || null,
        createdAt: new Date().toISOString()
      };
      await products.insertOne(product);
      delete product._id;
      res.json({ product });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'ajout du produit." });
    }
  });

  app.get('/api/products/mine', authMiddleware, async (req, res) => {
    try {
      const list = await products.find({ sellerId: req.seller.id }, { projection: { _id: 0 } }).toArray();
      res.json({ products: list });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors du chargement de vos produits." });
    }
  });

  app.delete('/api/products/:id', authMiddleware, async (req, res) => {
    try {
      const product = await products.findOne({ id: req.params.id });
      if (!product) return res.status(404).json({ error: "Produit introuvable." });
      if (product.sellerId !== req.seller.id) {
        return res.status(403).json({ error: "Ce n'est pas l'un de vos produits." });
      }
      await products.deleteOne({ id: req.params.id });
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la suppression." });
    }
  });

  // ---------- Commandes & commissions ----------
  // Enregistre une commande à partir du panier envoyé par le site.
  // Les prix ne sont JAMAIS pris depuis le panier du client : on relit
  // chaque produit en base pour connaître son vrai prix et son vendeur,
  // afin qu'un client ne puisse pas trafiquer le montant.
  app.post('/api/orders', async (req, res) => {
    try {
      const { items, paymentMethod } = req.body;
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "Panier vide." });
      }
      const bySeller = {}; // sellerId -> { sellerId, sellerName, subtotal }
      const orderItems = [];
      let total = 0;

      for (const it of items) {
        const product = await products.findOne({ id: it.productId });
        if (!product) continue;
        const qty = Math.max(1, Number(it.qty) || 1);
        const lineTotal = product.price * qty;
        total += lineTotal;
        orderItems.push({ productId: product.id, name: product.name, price: product.price, qty, sellerId: product.sellerId, sellerName: product.sellerName });
        if (!bySeller[product.sellerId]) {
          bySeller[product.sellerId] = { sellerId: product.sellerId, sellerName: product.sellerName, subtotal: 0 };
        }
        bySeller[product.sellerId].subtotal += lineTotal;
      }

      if (orderItems.length === 0) {
        return res.status(400).json({ error: "Aucun produit valide dans ce panier." });
      }

      const bySellerBreakdown = Object.values(bySeller).map(s => ({
        ...s,
        commission: Math.round(s.subtotal * COMMISSION_RATE),
        amountDue: Math.round(s.subtotal * (1 - COMMISSION_RATE))
      }));

      const order = {
        id: "o_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
        items: orderItems,
        total,
        paymentMethod: paymentMethod || 'whatsapp',
        bySeller: bySellerBreakdown,
        status: 'nouvelle', // à faire évoluer manuellement plus tard : livrée / payée au vendeur
        createdAt: new Date().toISOString()
      };
      await orders.insertOne(order);
      res.json({ orderId: order.id, total: order.total });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'enregistrement de la commande." });
    }
  });

  // Un vendeur connecté voit ses propres commandes et ce qui lui est dû (90%).
  app.get('/api/orders/mine', authMiddleware, async (req, res) => {
    try {
      const list = await orders.find(
        { "bySeller.sellerId": req.seller.id },
        { projection: { _id: 0 } }
      ).sort({ createdAt: -1 }).toArray();
      const mine = list.map(o => ({
        id: o.id,
        createdAt: o.createdAt,
        status: o.status,
        paymentMethod: o.paymentMethod,
        part: o.bySeller.find(s => s.sellerId === req.seller.id)
      }));
      res.json({ orders: mine });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors du chargement des commandes." });
    }
  });

  // ---------- Assistant shopping IA (aide les acheteurs à trouver un produit) ----------
  // Nécessite votre propre clé API Anthropic (console.anthropic.com), à mettre
  // dans la variable d'environnement ANTHROPIC_API_KEY sur Render. Sans elle,
  // l'assistant répond poliment qu'il n'est pas encore configuré — le reste
  // du site continue de fonctionner normalement.
  const CAT_LABELS = { mode: "Mode & Vêtements", beaute: "Beauté & Bien-être", epicerie: "Épicerie & Alimentation", artisanat: "Artisanat & Maison" };

  app.post('/api/assistant/chat', async (req, res) => {
    try {
      if (!ANTHROPIC_API_KEY) {
        return res.status(503).json({ error: "L'assistant n'est pas encore activé sur ce site (clé API à configurer)." });
      }
      const { message, history } = req.body;
      if (!message || typeof message !== 'string' || !message.trim()) {
        return res.status(400).json({ error: "Message manquant." });
      }

      const catalog = await products.find({}, { projection: { _id: 0, id: 1, name: 1, price: 1, cat: 1 } }).limit(300).toArray();
      const catalogText = catalog.length
        ? catalog.map(p => `- ${p.name} (${CAT_LABELS[p.cat] || p.cat}) — ${p.price} FCFA`).join('\n')
        : "Le catalogue est vide pour le moment.";

      const systemPrompt = `Tu es l'assistant shopping du site Amarita, un marché en ligne sénégalais (catégories : mode, beauté, épicerie, artisanat).
Voici le catalogue actuellement en vente :
${catalogText}

Règles strictes :
- Réponds toujours en français, de façon brève (2-4 phrases) et chaleureuse.
- Ne recommande QUE des produits présents dans la liste ci-dessus, avec leur vrai prix.
- Si rien ne correspond à la demande du client, dis-le honnêtement plutôt que d'inventer un produit, et propose la catégorie la plus proche.
- N'invente jamais de nom de produit, de prix, ou de stock.`;

      const messages = [
        ...(Array.isArray(history) ? history.slice(-6).filter(m => m && m.role && m.content) : []),
        { role: 'user', content: message.trim() }
      ];

      const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 400,
          system: systemPrompt,
          messages
        })
      });
      const data = await apiRes.json();
      if (!apiRes.ok) {
        console.error("Erreur API Anthropic:", data);
        return res.status(502).json({ error: "L'assistant n'a pas pu répondre pour l'instant, réessayez." });
      }
      const reply = (data.content || []).map(b => b.text || '').join('\n').trim() || "Désolé, je n'ai pas de réponse à vous donner.";
      res.json({ reply });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur de l'assistant." });
    }
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Serveur Amarita démarré sur le port ${PORT}, connecté à MongoDB.`));
}

start().catch(err => {
  console.error("Impossible de démarrer le serveur :", err);
  process.exit(1);
});
