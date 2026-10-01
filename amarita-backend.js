/**
 * Serveur unique pour Amarita — site + backend + vraie base de données
 * -----------------------------------------------------------------------
 * Un seul serveur qui :
 *   1. Affiche le site (index.html) à l'adresse principale
 *   2. Gère les comptes vendeurs (inscription / connexion par e-mail,
 *      ou connexion avec Apple)
 *   3. Gère l'ajout, la liste et la suppression de produits par les vendeurs
 *   4. Enregistre chaque commande et calcule la commission Amarita (10%
 *      détail / 3% grossiste) et la part due à chaque vendeur
 *   5. Paiement par Wave, Orange Money (liens/instructions simples) ou
 *      PayTech (carte, Orange Money, Wave, Free Money — unifiés)
 *   6. Si le paiement passe par PayTech : reverse AUTOMATIQUEMENT à chaque
 *      vendeur sa part, par virement mobile money (API Transfer PayTech).
 *      Pour Wave/Orange/WhatsApp (hors PayTech), le versement reste manuel :
 *      l'argent ne transite jamais par le solde PayTech d'Amarita dans ce cas.
 *
 * Les données (vendeurs, produits, commandes) sont stockées dans
 * MongoDB Atlas, gratuit et persistant.
 *
 * Installation :
 *   npm install
 *   MONGODB_URI=... JWT_SECRET=... APPLE_CLIENT_ID=... ANTHROPIC_API_KEY=... PAYTECH_API_KEY=... PAYTECH_API_SECRET=... PAYTECH_ENV=... BASE_URL=... npm start
 *
 * (nécessite Node.js 18 ou plus récent, pour que "fetch" soit disponible nativement)
 *
 * PAYTECH_API_KEY / PAYTECH_API_SECRET : à récupérer sur paytech.sn après
 * inscription (Dashboard → Paramètres → API). Le mode production (vrais
 * paiements) demande une validation manuelle par PayTech : envoyer NINEA,
 * pièce d'identité, registre de commerce à contact@paytech.sn. Sans cette
 * validation, seul PAYTECH_ENV=test fonctionne (montant débité aléatoire
 * entre 100 et 150 FCFA, jamais le vrai montant — normal, pas un bug).
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
// Render fait transiter les requêtes via un proxy en HTTPS→HTTP ; sans cette
// ligne, req.protocol renverrait "http" même en production, et PayTech
// refuse les URL de notification qui ne sont pas en https.
app.set('trust proxy', 1);
app.use(express.json({ limit: '6mb' })); // les photos de produits arrivent en base64 dans le JSON
app.use(express.urlencoded({ extended: true })); // les notifications IPN PayTech arrivent en formulaire classique

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
// Commission Amarita : deux segments vendeurs, plus un programme d'affiliation influenceur.
const COMMISSION_RATE_STANDARD = 0.10;  // vendeur détail (B2C)
const COMMISSION_RATE_GROSSISTE = 0.03; // vendeur grossiste (B2B)
// Part reversée à l'influenceur quand une vente passe par son lien/code de parrainage
// (prélevée SUR la commission Amarita, pas sur le prix de vente — le vendeur n'est jamais impacté).
const INFLUENCER_SHARE = 0.12;
// PayTech (paytech.sn) : agrégateur de paiement sénégalais qui encaisse (carte,
// Orange Money, Wave, Free Money) ET gère aussi les VIREMENTS sortants vers
// mobile money (API Transfer) — c'est ce qui permet d'envoyer automatiquement
// au vendeur ce qui lui est dû, dès que le paiement du client est passé par
// PayTech. À créer sur paytech.sn ; le mode production nécessite une
// validation manuelle (NINEA, pièce d'identité, registre de commerce — email
// à contact@paytech.sn). Sans validation, seul env=test fonctionne, et en
// test le montant débité est aléatoire (100-150 FCFA), pas le vrai montant.
const PAYTECH_API_KEY = process.env.PAYTECH_API_KEY || "";
const PAYTECH_API_SECRET = process.env.PAYTECH_API_SECRET || "";
const PAYTECH_ENV = process.env.PAYTECH_ENV || "test";
// Nécessaire pour construire l'URL de callback des virements PayTech
// (payoutSeller tourne parfois hors d'une requête HTTP classique, donc pas
// d'accès à req.get('host') à cet endroit-là).
const BASE_URL = process.env.BASE_URL || "https://amarita.onrender.com";
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
  const livreurs = db.collection('livreurs');
  const influenceurs = db.collection('influenceurs');
  await influenceurs.createIndex({ code: 1 }, { unique: true });

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
      const { name, email, password, sellerType, payoutPhone, payoutService } = req.body;
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
        sellerType: sellerType === 'grossiste' ? 'grossiste' : 'standard',
        payoutPhone: payoutPhone || null,
        payoutService: payoutService || null, // "Orange Money Senegal" | "Wave Senegal" | "Free Money Senegal"
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
      const allowedCats = ["mode", "beaute", "epicerie", "artisanat", "fournitures", "immobilier"];
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

  // Infos de versement automatique (numéro Wave/Orange du vendeur) — consultées
  // et modifiables depuis le tableau de bord vendeur, à tout moment.
  app.get('/api/sellers/me', authMiddleware, async (req, res) => {
    try {
      const seller = await sellers.findOne({ id: req.seller.id }, { projection: { _id: 0, passwordHash: 0 } });
      if (!seller) return res.status(404).json({ error: "Vendeur introuvable." });
      res.json({ seller });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
    }
  });

  app.put('/api/sellers/payout', authMiddleware, async (req, res) => {
    try {
      const { payoutPhone, payoutService } = req.body;
      const allowedServices = ["Wave Senegal", "Orange Money Senegal", "Free Money Senegal"];
      if (!payoutPhone || !allowedServices.includes(payoutService)) {
        return res.status(400).json({ error: "Numéro et opérateur valides requis." });
      }
      await sellers.updateOne({ id: req.seller.id }, { $set: { payoutPhone: payoutPhone.trim(), payoutService } });
      res.json({ ok: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
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

  // ---------- Candidatures livreurs ----------
  // Formulaire simple : les candidatures sont enregistrées, Amarita les
  // recontacte manuellement pour l'instant (pas d'attribution automatique
  // de commandes — ce serait une étape suivante, plus complexe).
  // ---------- Programme influenceurs (parrainage) ----------
  // Génère un code court, unique, facile à partager (ex: URL "?ref=CODE").
  function generateAffiliateCode(){
    return crypto.randomBytes(3).toString('hex').toUpperCase(); // ex: "A3F9C1"
  }

  app.post('/api/influenceurs', async (req, res) => {
    try {
      const { name, phone } = req.body;
      if (!name || !phone) {
        return res.status(400).json({ error: "Nom et téléphone requis." });
      }
      let code;
      do { code = generateAffiliateCode(); } while (await influenceurs.findOne({ code }));
      const influenceur = {
        id: "i_" + Date.now(),
        name, phone, code,
        createdAt: new Date().toISOString()
      };
      await influenceurs.insertOne(influenceur);
      res.json({ code, link: `${req.protocol}://${req.get('host')}/?ref=${code}` });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
    }
  });

  // Un influenceur consulte ses gains avec son code — pas besoin de mot de
  // passe séparé, le code fait office de clé (comme un lien de suivi de colis).
  app.get('/api/influenceurs/:code/gains', async (req, res) => {
    try {
      const code = req.params.code.trim().toUpperCase();
      const influenceur = await influenceurs.findOne({ code });
      if (!influenceur) return res.status(404).json({ error: "Code introuvable." });
      const list = await orders.find({ affiliateCode: code }, { projection: { _id: 0 } }).sort({ createdAt: -1 }).toArray();
      const totalGains = list.reduce((sum, o) => sum + o.bySeller.reduce((s2, b) => s2 + (b.influencerFee || 0), 0), 0);
      res.json({
        name: influenceur.name,
        code,
        totalGains,
        nbCommandes: list.length,
        commandes: list.map(o => ({
          createdAt: o.createdAt,
          total: o.total,
          gain: o.bySeller.reduce((s2, b) => s2 + (b.influencerFee || 0), 0)
        }))
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
    }
  });

  app.post('/api/livreurs', async (req, res) => {
    try {
      const { name, phone, vehicule, zone } = req.body;
      if (!name || !phone || !vehicule || !zone) {
        return res.status(400).json({ error: "Tous les champs sont requis." });
      }
      await livreurs.insertOne({
        id: "l_" + Date.now(),
        name, phone, vehicule, zone,
        status: 'nouvelle_candidature',
        createdAt: new Date().toISOString()
      });
      res.json({ ok: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'envoi de la candidature." });
    }
  });

  // ---------- Commandes & commissions ----------
  // Enregistre une commande à partir du panier envoyé par le site.
  // Les prix ne sont JAMAIS pris depuis le panier du client : on relit
  // chaque produit en base pour connaître son vrai prix et son vendeur,
  // afin qu'un client ne puisse pas trafiquer le montant.
  app.post('/api/orders', async (req, res) => {
    try {
      const { items, paymentMethod, affiliateCode } = req.body;
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "Panier vide." });
      }

      // Vérifie le code de parrainage influenceur, s'il y en a un. Un code
      // invalide n'empêche jamais la commande : il est simplement ignoré.
      let influencer = null;
      if (affiliateCode) {
        influencer = await influenceurs.findOne({ code: affiliateCode.trim().toUpperCase() });
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

      // Le taux de base dépend du type de chaque vendeur (grossiste 3% / détail 10%).
      const bySellerBreakdown = [];
      for (const s of Object.values(bySeller)) {
        const sellerDoc = await sellers.findOne({ id: s.sellerId }, { projection: { sellerType: 1 } });
        const rate = (sellerDoc && sellerDoc.sellerType === 'grossiste') ? COMMISSION_RATE_GROSSISTE : COMMISSION_RATE_STANDARD;
        const commission = s.subtotal * rate;
        const influencerFee = influencer ? commission * INFLUENCER_SHARE : 0;
        bySellerBreakdown.push({
          ...s,
          commissionRate: rate,
          commission: Math.round(commission),
          amountDue: Math.round(s.subtotal - commission), // part du vendeur, jamais affectée par l'influenceur
          influencerFee: Math.round(influencerFee),
          platformNet: Math.round(commission - influencerFee)
        });
      }

      const order = {
        id: "o_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
        items: orderItems,
        total,
        paymentMethod: paymentMethod || 'whatsapp',
        bySeller: bySellerBreakdown,
        affiliateId: influencer ? influencer.id : null,
        affiliateCode: influencer ? influencer.code : null,
        hasAffiliate: !!influencer,
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
      const mine = list.map(o => {
        const part = o.bySeller.find(s => s.sellerId === req.seller.id);
        return {
          id: o.id,
          createdAt: o.createdAt,
          status: o.status,
          paymentMethod: o.paymentMethod,
          part,
          payoutStatus: part ? (part.payoutStatus || 'non_verse') : 'non_verse'
        };
      });
      res.json({ orders: mine });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors du chargement des commandes." });
    }
  });

  // ---------- PayTech : paiement + virement automatique aux vendeurs ----------
  // Le virement automatique n'est possible QUE pour les commandes payées via
  // PayTech (Wave/WhatsApp restent manuels : l'argent ne transite jamais par
  // le solde PayTech d'Amarita dans ces cas, donc rien à reverser depuis là).
  function verifyPaytechHmac(message, receivedHmac){
    if (!receivedHmac) return false;
    const expected = crypto.createHmac('sha256', PAYTECH_API_SECRET).update(message).digest('hex');
    try {
      return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(receivedHmac));
    } catch { return false; }
  }

  app.post('/api/paytech/request-payment', async (req, res) => {
    try {
      if (!PAYTECH_API_KEY || !PAYTECH_API_SECRET) {
        return res.status(503).json({ error: "PayTech n'est pas encore configuré (clés API manquantes)." });
      }
      const { orderId } = req.body;
      const order = await orders.findOne({ id: orderId });
      if (!order) return res.status(404).json({ error: "Commande introuvable — appelez /api/orders d'abord." });

      const payRes = await fetch("https://paytech.sn/api/payment/request-payment", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API_KEY": PAYTECH_API_KEY,
          "API_SECRET": PAYTECH_API_SECRET
        },
        body: JSON.stringify({
          item_name: "Commande Amarita",
          item_price: order.total,
          currency: "XOF",
          ref_command: order.id,
          command_name: `Commande Amarita ${order.id}`,
          env: PAYTECH_ENV,
          ipn_url: `${req.protocol}://${req.get('host')}/api/paytech/ipn`,
          success_url: `${req.protocol}://${req.get('host')}/?payment=success`,
          cancel_url: `${req.protocol}://${req.get('host')}/?payment=cancel`,
          custom_field: JSON.stringify({ orderId: order.id })
        })
      });
      const data = await payRes.json();
      if (data.success === 1) {
        res.json({ redirect_url: data.redirect_url });
      } else {
        res.status(400).json({ error: data.message || "Réponse PayTech invalide." });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la demande de paiement." });
    }
  });

  // Envoie automatiquement à un vendeur ce qui lui est dû, via l'API Transfer
  // PayTech. Ne fait rien (silencieusement) si le vendeur n'a pas renseigné
  // de numéro de versement — son dû reste visible dans son tableau de bord
  // pour un virement manuel en attendant.
  async function payoutSeller(orderId, sellerId){
    const order = await orders.findOne({ id: orderId });
    if (!order) return;
    const part = order.bySeller.find(s => s.sellerId === sellerId);
    if (!part || part.payoutStatus === 'verse' || part.payoutStatus === 'en_cours') return;

    const seller = await sellers.findOne({ id: sellerId });
    if (!seller || !seller.payoutPhone || !seller.payoutService) {
      await orders.updateOne(
        { id: orderId, "bySeller.sellerId": sellerId },
        { $set: { "bySeller.$.payoutStatus": 'non_verse' } }
      );
      return;
    }

    try {
      const transferRes = await fetch("https://paytech.sn/api/transfer/transferFund", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API_KEY": PAYTECH_API_KEY,
          "API_SECRET": PAYTECH_API_SECRET
        },
        body: JSON.stringify({
          amount: part.amountDue,
          destination_number: seller.payoutPhone,
          service: seller.payoutService,
          callback_url: `${BASE_URL}/api/paytech/transfer-ipn`,
          external_id: `${orderId}::${sellerId}`
        })
      });
      const data = await transferRes.json();
      const newStatus = (data.success === 1) ? 'en_cours' : 'echec';
      await orders.updateOne(
        { id: orderId, "bySeller.sellerId": sellerId },
        { $set: { "bySeller.$.payoutStatus": newStatus, "bySeller.$.transferId": data.transfer?.id_transfer || null } }
      );
    } catch (err) {
      console.error("Échec virement vendeur :", err);
      await orders.updateOne(
        { id: orderId, "bySeller.sellerId": sellerId },
        { $set: { "bySeller.$.payoutStatus": 'echec' } }
      );
    }
  }

  // Notification de PAIEMENT (le client a payé). Déclenche le virement
  // automatique vers chaque vendeur de la commande.
  app.post('/api/paytech/ipn', async (req, res) => {
    try {
      const { type_event, ref_command, item_price, api_key_sha256, api_secret_sha256, hmac_compute } = req.body;
      const hmacMessage = `${item_price}|${ref_command}|${PAYTECH_API_KEY}`;
      const validHmac = verifyPaytechHmac(hmacMessage, hmac_compute);
      const expectedKeyHash = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
      const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');
      const validSha = (api_key_sha256 === expectedKeyHash && api_secret_sha256 === expectedSecretHash);
      if (!validHmac && !validSha) {
        return res.status(403).send("IPN KO — signature invalide");
      }

      const order = await orders.findOne({ id: ref_command });
      if (!order) return res.status(200).send("IPN OK (commande introuvable, ignorée)");

      if (type_event === 'sale_complete') {
        await orders.updateOne({ id: ref_command }, { $set: { paymentStatus: 'payee' } });
        // Virement automatique à chaque vendeur de la commande.
        for (const s of order.bySeller) {
          await payoutSeller(ref_command, s.sellerId);
        }
      } else if (type_event === 'sale_canceled') {
        await orders.updateOne({ id: ref_command }, { $set: { paymentStatus: 'annulee' } });
      }
      res.send("IPN OK");
    } catch (err) {
      console.error(err);
      res.status(500).send("Erreur IPN");
    }
  });

  // Notification de VIREMENT (confirmation que l'argent est bien arrivé chez le vendeur).
  app.post('/api/paytech/transfer-ipn', async (req, res) => {
    try {
      const { type_event, amount, id_transfer, api_key_sha256, api_secret_sha256, hmac_compute, external_id } = req.body;
      const hmacMessage = `${amount}|${id_transfer}|${PAYTECH_API_KEY}`;
      const validHmac = verifyPaytechHmac(hmacMessage, hmac_compute);
      const expectedKeyHash = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
      const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');
      const validSha = (api_key_sha256 === expectedKeyHash && api_secret_sha256 === expectedSecretHash);
      if (!validHmac && !validSha) {
        return res.status(403).send("IPN KO — signature invalide");
      }

      const [orderId, sellerId] = (external_id || '').split('::');
      const newStatus = type_event === 'transfer_success' ? 'verse' : (type_event === 'transfer_failed' ? 'echec' : null);
      if (orderId && sellerId && newStatus) {
        await orders.updateOne(
          { id: orderId, "bySeller.sellerId": sellerId },
          { $set: { "bySeller.$.payoutStatus": newStatus } }
        );
      }
      res.send("IPN OK");
    } catch (err) {
      console.error(err);
      res.status(500).send("Erreur IPN transfer");
    }
  });

  // ---------- Assistant shopping IA (aide les acheteurs à trouver un produit) ----------
  // Nécessite votre propre clé API Anthropic (console.anthropic.com), à mettre
  // dans la variable d'environnement ANTHROPIC_API_KEY sur Render. Sans elle,
  // l'assistant répond poliment qu'il n'est pas encore configuré — le reste
  // du site continue de fonctionner normalement.
  const CAT_LABELS = { mode: "Mode & Vêtements", beaute: "Beauté & Bien-être", epicerie: "Épicerie & Alimentation", artisanat: "Artisanat & Maison", fournitures: "Fournitures", immobilier: "Immobilier" };

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
