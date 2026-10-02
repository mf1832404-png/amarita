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

const JWT_SECRET = (process.env.JWT_SECRET || "").trim();
if (!JWT_SECRET && process.env.NODE_ENV === "production") {
  console.error("❌ JWT_SECRET est obligatoire en production.");
  process.exit(1);
}
if (JWT_SECRET && JWT_SECRET.length < 32 && process.env.NODE_ENV === "production") {
  console.error("❌ JWT_SECRET doit contenir au moins 32 caractères en production.");
  process.exit(1);
}
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
const AMARITA_ADMIN_KEY = (process.env.AMARITA_ADMIN_KEY || "").trim();

// Limiteur simple en mémoire pour ralentir les abus sur les routes sensibles.
const rateBuckets = new Map();
function rateLimit(windowMs, max, keyPrefix){
  return (req,res,next)=>{
    const key = `${keyPrefix}:${req.ip || 'unknown'}`;
    const now = Date.now();
    let b = rateBuckets.get(key);
    if(!b || now - b.start >= windowMs) b = {start:now,count:0};
    b.count++; rateBuckets.set(key,b);
    if(b.count > max) return res.status(429).json({error:'Trop de tentatives. Réessayez dans quelques instants.'});
    next();
  };
}
setInterval(()=>{ const now=Date.now(); for(const [k,b] of rateBuckets){ if(now-b.start>15*60*1000) rateBuckets.delete(k); } }, 15*60*1000).unref();

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
  const reviews = db.collection('reviews');
  const supportTickets = db.collection('support_tickets');
  const orderEvents = db.collection('order_events');
  await reviews.createIndex({ orderId: 1 }, { unique: true });
  await supportTickets.createIndex({ id: 1 }, { unique: true });
  await orderEvents.createIndex({ orderId: 1, createdAt: -1 });
  await influenceurs.createIndex({ code: 1 }, { unique: true });

  // Une même adresse e-mail ne peut créer qu'un seul compte vendeur
  // (que ce soit par mot de passe ou par Apple).
  await sellers.createIndex({ email: 1 }, { unique: true });

  app.get('/api/health', (req, res) => {
    res.send('✅ Serveur Amarita en ligne — site, comptes vendeurs, commandes et assistant IA actifs (base de données connectée).');
  });

  // ---------- Comptes vendeurs ----------
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  app.post('/api/auth/signup', rateLimit(60*1000, 10, 'auth_signup'), async (req, res) => {
    try {
      const { name, password, sellerType, payoutPhone, payoutService } = req.body;
      const email = String(req.body.email || '').trim().toLowerCase();
      if (!name || !email || !password) {
        return res.status(400).json({ error: "Nom, e-mail et mot de passe requis." });
      }
      if (!EMAIL_RE.test(email)) {
        return res.status(400).json({ error: "Adresse e-mail invalide." });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: "Le mot de passe doit faire au moins 8 caractères." });
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
        passwordHash: bcrypt.hashSync(password, 12),
        createdAt: new Date().toISOString()
      };
      await sellers.insertOne(seller);
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, seller: { id: seller.id, name: seller.name } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
    }
  });

  app.post('/api/auth/login', rateLimit(60*1000, 10, 'auth_login'), async (req, res) => {
    try {
      const email = String(req.body.email || '').trim().toLowerCase();
      const { password } = req.body;
      const seller = await sellers.findOne({ email });
      if (!seller || seller.authProvider === 'apple' || !bcrypt.compareSync(password || '', seller.passwordHash || '')) {
        return res.status(401).json({ error: "E-mail ou mot de passe incorrect." });
      }
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, seller: { id: seller.id, name: seller.name } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la connexion." });
    }
  });

  // Connexion / inscription automatique via "Se connecter avec Apple".
  // Le frontend envoie le id_token reçu d'Apple ; on le vérifie ici
  // auprès d'Apple avant de faire confiance à l'e-mail qu'il contient.
  app.post('/api/auth/apple', rateLimit(60*1000, 10, 'auth_apple'), async (req, res) => {
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
      const email = String(applePayload.email || '').trim().toLowerCase();
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
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '7d' });
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
      const numericPrice = Number(price);
      if (!name || !Number.isFinite(numericPrice) || numericPrice <= 0 || !allowedCats.includes(cat)) {
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
        price: Math.round(numericPrice),
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

  // ---------- Réseau de livreurs indépendants Amarita ----------
  // Les livreurs ne sont pas salariés d'Amarita : ils candidatent comme
  // partenaires indépendants, indiquent leur zone et leur véhicule, puis
  // peuvent se déclarer disponibles pour recevoir des courses.
  await livreurs.createIndex({ id: 1 }, { unique: true });
  await livreurs.createIndex({ phone: 1 }, { unique: true });
  await livreurs.createIndex({ email: 1 }, { sparse: true, unique: true });

  // Candidature d'un livreur indépendant.
  // Après validation, son statut peut passer à "actif".
  // Le système de courses ci-dessous permet ensuite l'attribution volontaire.
  // Aucun statut "salarié" ou contrat de travail n'est créé par le backend.
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

  // ---------- Livreurs indépendants : comptes + courses ----------
  // Un livreur Amarita est un partenaire indépendant. Son compte est séparé
  // des comptes vendeurs et reçoit un JWT portant role=livreur.
  function livreurToken(livreur){
    return jwt.sign(
      { id: livreur.id, name: livreur.name, role: 'livreur' },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
  }

  function requireAdmin(req, res, next){
    if (!AMARITA_ADMIN_KEY) return res.status(503).json({ error: "AMARITA_ADMIN_KEY n'est pas configurée." });
    const key = req.headers['x-amarita-admin-key'];
    if (!key || key !== AMARITA_ADMIN_KEY) return res.status(401).json({ error: "Accès administrateur requis." });
    next();
  }

  function authLivreur(req, res, next){
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Connexion livreur requise." });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (payload.role !== 'livreur') return res.status(403).json({ error: "Compte livreur requis." });
      req.livreur = payload;
      next();
    } catch {
      return res.status(401).json({ error: "Session livreur invalide ou expirée." });
    }
  }

  // Candidature d'un livreur indépendant. Le mot de passe est facultatif
  // pour préserver les anciennes candidatures ; il sera obligatoire pour
  // ouvrir une session, après activation du compte.
  app.post('/api/livreurs', async (req, res) => {
    try {
      const { name, phone, email, password, vehicule, zone } = req.body;
      if (!name || !phone || !vehicule || !zone) {
        return res.status(400).json({ error: "Nom, téléphone, véhicule et zone sont requis." });
      }
      if (password && String(password).length < 8) {
        return res.status(400).json({ error: "Le mot de passe doit faire au moins 8 caractères." });
      }
      const normalizedPhone = String(phone).trim();
      const normalizedEmail = email ? String(email).trim().toLowerCase() : null;
      if (await livreurs.findOne({ phone: normalizedPhone })) {
        return res.status(409).json({ error: "Un compte/candidature existe déjà avec ce numéro." });
      }
      if (normalizedEmail && await livreurs.findOne({ email: normalizedEmail })) {
        return res.status(409).json({ error: "Un compte/candidature existe déjà avec cet e-mail." });
      }
      const livreur = {
        id: "l_" + crypto.randomUUID(),
        name: String(name).trim(),
        phone: normalizedPhone,
        email: normalizedEmail,
        vehicule: String(vehicule).trim(),
        zone: String(zone).trim(),
        status: 'nouvelle_candidature',
        available: false,
        passwordHash: password ? bcrypt.hashSync(String(password), 12) : null,
        createdAt: new Date().toISOString()
      };
      await livreurs.insertOne(livreur);
      res.json({ ok: true, livreurId: livreur.id, status: livreur.status });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'envoi de la candidature." });
    }
  });

  // Activation administrative après vérification de la candidature.
  app.put('/api/livreurs/admin/:id/activation', requireAdmin, async (req, res) => {
    try {
      const { active, password } = req.body;
      if (typeof active !== 'boolean') return res.status(400).json({ error: "active doit être true ou false." });
      if (active && password && String(password).length < 8) return res.status(400).json({ error: "Mot de passe trop court." });
      const update = { status: active ? 'actif' : 'refuse', available: false, updatedAt: new Date().toISOString() };
      if (password) update.passwordHash = bcrypt.hashSync(String(password), 12);
      const result = await livreurs.updateOne({ id: req.params.id }, { $set: update });
      if (!result.matchedCount) return res.status(404).json({ error: "Livreur introuvable." });
      res.json({ ok: true, status: update.status });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
    }
  });

  app.post('/api/livreurs/login', async (req, res) => {
    try {
      const phone = String(req.body.phone || '').trim();
      const password = String(req.body.password || '');
      if (!phone || !password) return res.status(400).json({ error: "Téléphone et mot de passe requis." });
      const livreur = await livreurs.findOne({ phone });
      if (!livreur || livreur.status !== 'actif' || !livreur.passwordHash || !bcrypt.compareSync(password, livreur.passwordHash)) {
        return res.status(401).json({ error: "Identifiants livreur incorrects ou compte non activé." });
      }
      const token = livreurToken(livreur);
      res.json({ token, livreur: { id: livreur.id, name: livreur.name, phone: livreur.phone, zone: livreur.zone, vehicule: livreur.vehicule, available: !!livreur.available } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la connexion livreur." });
    }
  });

  app.get('/api/livreurs/me', authLivreur, async (req, res) => {
    const livreur = await livreurs.findOne({ id: req.livreur.id }, { projection: { _id: 0, passwordHash: 0 } });
    if (!livreur) return res.status(404).json({ error: "Livreur introuvable." });
    res.json({ livreur });
  });

  app.put('/api/livreurs/disponibilite', authLivreur, async (req, res) => {
    try {
      const { available } = req.body;
      if (typeof available !== 'boolean') return res.status(400).json({ error: "available doit être true ou false." });
      const result = await livreurs.updateOne(
        { id: req.livreur.id, status: 'actif' },
        { $set: { available, lastAvailabilityAt: new Date().toISOString() } }
      );
      if (!result.matchedCount) return res.status(404).json({ error: "Livreur actif introuvable." });
      res.json({ ok: true, available });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
    }
  });

  // Compatibilité avec l'ancien endpoint : il n'accepte plus un ID arbitraire.
  app.put('/api/livreurs/:id/disponibilite', authLivreur, async (req, res) => {
    try {
      if (req.params.id !== req.livreur.id) return res.status(403).json({ error: "Vous ne pouvez modifier que votre propre disponibilité." });
      const { available } = req.body;
      if (typeof available !== 'boolean') return res.status(400).json({ error: "available doit être true ou false." });
      const result = await livreurs.updateOne(
        { id: req.livreur.id, status: 'actif' },
        { $set: { available, lastAvailabilityAt: new Date().toISOString() } }
      );
      if (!result.matchedCount) return res.status(404).json({ error: "Livreur actif introuvable." });
      res.json({ ok: true, available });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
    }
  });

  // Crée une course. Cette opération est administrative/interne : elle exige
  // la clé d'administration afin qu'un visiteur ne puisse pas injecter de
  // fausses courses dans le réseau de livreurs.
  app.post('/api/livraisons', requireAdmin, async (req, res) => {
    try {
      const { orderId, pickupZone, deliveryZone, pickupAddress, deliveryAddress, deliveryFee } = req.body;
      if (!orderId || !pickupZone || !deliveryZone || !deliveryAddress) {
        return res.status(400).json({ error: "Commande, zones et adresse de livraison requis." });
      }
      const order = await orders.findOne({ id: orderId });
      if (!order) return res.status(404).json({ error: "Commande introuvable." });
      const existing = await db.collection('livraisons').findOne({ orderId, status: { $nin: ['livree', 'annulee'] } });
      if (existing) return res.status(409).json({ error: "Une course active existe déjà pour cette commande.", livraisonId: existing.id });
      const course = {
        id: "c_" + crypto.randomUUID(),
        orderId,
        pickupZone: String(pickupZone).trim(),
        deliveryZone: String(deliveryZone).trim(),
        pickupAddress: pickupAddress ? String(pickupAddress).trim() : null,
        deliveryAddress: String(deliveryAddress).trim(),
        deliveryFee: Math.max(0, Math.round(Number(deliveryFee) || 0)),
        livreurId: null,
        status: 'a_attribuer',
        createdAt: new Date().toISOString()
      };
      await db.collection('livraisons').insertOne(course);
      res.json({ ok: true, livraisonId: course.id, status: course.status });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la création de la course." });
    }
  });

  // Courses disponibles dans la zone du livreur connecté.
  app.get('/api/livraisons/disponibles', authLivreur, async (req, res) => {
    try {
      const livreur = await livreurs.findOne({ id: req.livreur.id, status: 'actif', available: true });
      if (!livreur) return res.status(403).json({ error: "Activez votre disponibilité pour voir les courses." });
      const list = await db.collection('livraisons').find({
        status: 'a_attribuer',
        deliveryZone: livreur.zone
      }, { projection: { _id: 0, deliveryAddress: 0 } }).sort({ createdAt: 1 }).toArray();
      res.json({ livraisons: list });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur." });
    }
  });

  app.get('/api/livraisons/mes-courses', authLivreur, async (req, res) => {
    const list = await db.collection('livraisons').find({ livreurId: req.livreur.id }, { projection: { _id: 0 } }).sort({ createdAt: -1 }).limit(100).toArray();
    res.json({ livraisons: list });
  });

  // Un livreur actif accepte volontairement une course. Le filtre status=a_attribuer
  // rend l'attribution atomique : le premier qui l'obtient gagne la course.
  app.post('/api/livraisons/:id/accepter', authLivreur, async (req, res) => {
    try {
      const livreur = await livreurs.findOne({ id: req.livreur.id, status: 'actif', available: true });
      if (!livreur) return res.status(403).json({ error: "Livreur non disponible ou non validé." });
      const result = await db.collection('livraisons').findOneAndUpdate(
        { id: req.params.id, status: 'a_attribuer' },
        { $set: { livreurId: req.livreur.id, livreurName: req.livreur.name, livreurPhone: livreur.phone || null, status: 'acceptee', acceptedAt: new Date().toISOString(), updatedAt: new Date().toISOString() } },
        { returnDocument: 'after', projection: { _id: 0 } }
      );
      if (!result) return res.status(409).json({ error: "Cette course vient d'être attribuée à un autre livreur." });
      await livreurs.updateOne({ id: req.livreur.id }, { $set: { available: false } });
      await logOrderEvent(result.orderId, 'acceptee', `Livreur ${req.livreur.name} attribué.`);
      res.json({ ok: true, livraison: result });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'acceptation de la course." });
    }
  });

  app.put('/api/livraisons/:id/position', authLivreur, async (req, res) => {
    try {
      const lat = Number(req.body.lat), lng = Number(req.body.lng);
      if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) return res.status(400).json({ error: 'Position GPS invalide.' });
      const course = await db.collection('livraisons').findOne({ id: req.params.id, livreurId: req.livreur.id, status: { $in: ['acceptee','recuperee','en_livraison'] } });
      if (!course) return res.status(404).json({ error: 'Course active introuvable.' });
      await db.collection('livraisons').updateOne({ id: course.id }, { $set: { currentLocation: { lat: Number(lat.toFixed(5)), lng: Number(lng.toFixed(5)), updatedAt: new Date().toISOString() }, updatedAt: new Date().toISOString() } });
      res.json({ ok: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur lors de la mise à jour GPS.' }); }
  });

  app.put('/api/livraisons/:id/statut', authLivreur, async (req, res) => {
    try {
      const { status } = req.body;
      const transitions = { acceptee: ['recuperee'], recuperee: ['en_livraison'], en_livraison: ['livree'] };
      const course = await db.collection('livraisons').findOne({ id: req.params.id, livreurId: req.livreur.id });
      if (!course) return res.status(404).json({ error: "Course introuvable pour ce livreur." });
      if (!transitions[course.status] || !transitions[course.status].includes(status)) {
        return res.status(409).json({ error: `Transition impossible : ${course.status} → ${status}.` });
      }
      await db.collection('livraisons').updateOne(
        { id: course.id, livreurId: req.livreur.id, status: course.status },
        { $set: { status, updatedAt: new Date().toISOString(), ...(status === 'recuperee' ? { pickedUpAt: new Date().toISOString() } : {}), ...(status === 'en_livraison' ? { inDeliveryAt: new Date().toISOString() } : {}), ...(status === 'livree' ? { deliveredAt: new Date().toISOString() } : {}) } }
      );
      if (status === 'livree') {
        await livreurs.updateOne({ id: req.livreur.id }, { $set: { available: true } });
        const courseNow = await db.collection('livraisons').findOne({ id: req.params.id });
        if (courseNow) { await orders.updateOne({ id: courseNow.orderId }, { $set: { status: 'livree' } }); await logOrderEvent(courseNow.orderId, 'livree', 'Commande livrée.'); }
      } else {
        const courseNow = await db.collection('livraisons').findOne({ id: req.params.id });
        if (courseNow) await logOrderEvent(courseNow.orderId, status, `Livraison : ${status}.`);
      }
      res.json({ ok: true, status });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la mise à jour de la course." });
    }
  });

  function publicOrder(order, delivery = null){
    return {
      id: order.id,
      createdAt: order.createdAt,
      status: order.status,
      paymentStatus: order.paymentStatus,
      total: order.total,
      paymentMethod: order.paymentMethod,
      delivery: delivery ? {
        pickupZone: delivery.pickupZone,
        deliveryZone: delivery.deliveryZone,
        fee: delivery.deliveryFee,
        status: delivery.status,
        livreur: delivery.livreurId ? { id: delivery.livreurId, name: delivery.livreurName || null, phone: delivery.livreurPhone || null } : null,
        updatedAt: delivery.updatedAt || null,
        currentLocation: delivery.currentLocation && ['acceptee','recuperee','en_livraison'].includes(delivery.status) ? delivery.currentLocation : null
      } : null,
      items: order.items.map(i => ({ name: i.name, price: i.price, qty: i.qty }))
    };
  }

  async function logOrderEvent(orderId, type, message){
    await orderEvents.insertOne({ id: crypto.randomUUID(), orderId, type, message, createdAt: new Date().toISOString() });
  }

  // ---------- Commandes & commissions ----------
  // Enregistre une commande à partir du panier envoyé par le site.
  // Les prix ne sont JAMAIS pris depuis le panier du client : on relit
  // chaque produit en base pour connaître son vrai prix et son vendeur,
  // afin qu'un client ne puisse pas trafiquer le montant.
  app.post('/api/orders', rateLimit(60*1000, 20, 'orders'), async (req, res) => {
    try {
      const { items, paymentMethod, affiliateCode, delivery, customer } = req.body;
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

      const deliveryFee = delivery && delivery.address ? Math.max(0, Math.round(Number(delivery.fee) || 0)) : 0;
      const order = {
        id: "o_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
        items: orderItems,
        total: total + deliveryFee,
        productSubtotal: total,
        deliveryFee,
        paymentMethod: paymentMethod || 'whatsapp',
        bySeller: bySellerBreakdown,
        affiliateId: influencer ? influencer.id : null,
        affiliateCode: influencer ? influencer.code : null,
        hasAffiliate: !!influencer,
        status: 'nouvelle',
        paymentStatus: 'en_attente',
        customer: customer ? { name: String(customer.name || '').trim().slice(0,120), phone: String(customer.phone || '').trim().slice(0,40) } : null,
        trackingToken: crypto.randomBytes(24).toString('hex'),
        delivery: delivery && delivery.address ? {
          pickupZone: String(delivery.pickupZone || '').trim(),
          deliveryZone: String(delivery.deliveryZone || '').trim(),
          pickupAddress: delivery.pickupAddress ? String(delivery.pickupAddress).trim() : null,
          address: String(delivery.address).trim(),
          fee: deliveryFee
        } : null,
        createdAt: new Date().toISOString()
      };
      await orders.insertOne(order);
      await logOrderEvent(order.id, 'commande_creee', 'Commande enregistrée.');

      // Si le client fournit une adresse, on prépare immédiatement la course,
      // mais elle reste invisible aux livreurs tant que le paiement n'est pas
      // confirmé. Cela évite qu'un livreur accepte une course non payée.
      if (order.delivery && order.delivery.deliveryZone) {
        await db.collection('livraisons').insertOne({
          id: 'c_' + crypto.randomUUID(),
          orderId: order.id,
          pickupZone: order.delivery.pickupZone || 'À définir',
          deliveryZone: order.delivery.deliveryZone,
          pickupAddress: order.delivery.pickupAddress,
          deliveryAddress: order.delivery.address,
          deliveryFee: order.delivery.fee,
          livreurId: null,
          status: 'en_attente_paiement',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        });
      }
      res.json({ orderId: order.id, total: order.total, trackingToken: order.trackingToken });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de l'enregistrement de la commande." });
    }
  });

  // ---------- Expérience client : suivi, avis et assistance ----------
  app.get('/api/orders/track/:token', async (req, res) => {
    try {
      const order = await orders.findOne({ trackingToken: req.params.token }, { projection: { _id: 0, trackingToken: 0, bySeller: 0, affiliateId: 0, affiliateCode: 0 } });
      if (!order) return res.status(404).json({ error: 'Commande introuvable.' });
      const delivery = await db.collection('livraisons').findOne({ orderId: order.id }, { projection: { _id: 0, deliveryAddress: 0, pickupAddress: 0 } });
      const events = await orderEvents.find({ orderId: order.id }, { projection: { _id: 0, orderId: 0 } }).sort({ createdAt: 1 }).toArray();
      const review = await reviews.findOne({ orderId: order.id }, { projection: { _id: 0 } });
      res.json({ order: publicOrder(order, delivery), events, review });
    } catch (err) {
      console.error(err); res.status(500).json({ error: 'Erreur lors du suivi de la commande.' });
    }
  });

  app.post('/api/orders/:id/review', async (req, res) => {
    try {
      const { trackingToken, rating, deliveryRating, comment } = req.body;
      const order = await orders.findOne({ id: req.params.id, trackingToken });
      if (!order) return res.status(403).json({ error: 'Commande non autorisée.' });
      if (order.status !== 'livree') return res.status(400).json({ error: 'L’avis sera disponible après la livraison.' });
      const r = Math.max(1, Math.min(5, Number(rating)));
      const dr = deliveryRating == null ? null : Math.max(1, Math.min(5, Number(deliveryRating)));
      await reviews.updateOne({ orderId: order.id }, { $set: { orderId: order.id, rating: r, deliveryRating: dr, comment: String(comment || '').trim().slice(0,1000), createdAt: new Date().toISOString() } }, { upsert: true });
      res.json({ ok: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Impossible d’enregistrer l’avis.' }); }
  });

  app.post('/api/support', rateLimit(60*1000, 10, 'support'), async (req, res) => {
    try {
      const { trackingToken, orderId, category, message, phone } = req.body;
      if (!message || !String(message).trim()) return res.status(400).json({ error: 'Message requis.' });
      let verifiedOrder = null;
      if (orderId && trackingToken) verifiedOrder = await orders.findOne({ id: orderId, trackingToken });
      const ticket = { id: 't_' + crypto.randomUUID(), orderId: verifiedOrder ? verifiedOrder.id : null, category: String(category || 'autre').slice(0,60), message: String(message).trim().slice(0,2000), phone: String(phone || '').trim().slice(0,40), status: 'ouvert', createdAt: new Date().toISOString() };
      await supportTickets.insertOne(ticket);
      res.json({ ok: true, ticketId: ticket.id });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Impossible d’ouvrir la demande d’assistance.' }); }
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
        await orders.updateOne({ id: ref_command }, { $set: { paymentStatus: 'payee', status: 'payee' } });
        await logOrderEvent(ref_command, 'paiement_confirme', 'Paiement confirmé.');
        await logOrderEvent(ref_command, 'a_attribuer', 'La commande est disponible pour attribution à un livreur.');
        await db.collection('livraisons').updateOne(
          { orderId: ref_command, status: 'en_attente_paiement' },
          { $set: { status: 'a_attribuer', paymentConfirmedAt: new Date().toISOString(), updatedAt: new Date().toISOString() } }
        );
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

  app.post('/api/assistant/chat', rateLimit(60*1000, 20, 'assistant_chat'), async (req, res) => {
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
