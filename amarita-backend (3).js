/**
 * Serveur unique pour Amarita — site + backend + vraie base de données
 * -----------------------------------------------------------------------
 * Un seul serveur qui :
 *   1. Affiche le site (index.html) à l'adresse principale
 *   2. Gère les comptes vendeurs (inscription / connexion)
 *   3. Gère l'ajout, la liste et la suppression de produits par les vendeurs
 *   4. Gère le paiement par carte via PayTech
 *
 * Les données (vendeurs et produits) sont maintenant stockées dans
 * MongoDB Atlas, gratuit et persistant — plus de risque de tout perdre
 * à un redémarrage du serveur, contrairement à l'ancienne version qui
 * utilisait un simple fichier data.json.
 *
 * Installation :
 *   npm install
 *   MONGODB_URI=... JWT_SECRET=... PAYTECH_API_KEY=... PAYTECH_API_SECRET=... BASE_URL=https://votre-domaine.sn npm start
 *
 * (nécessite Node.js 18 ou plus récent, pour que "fetch" soit disponible nativement)
 *
 * MONGODB_URI : à récupérer sur mongodb.com/cloud/atlas, après avoir créé
 * un cluster gratuit (M0) — voir les instructions données à côté de ce
 * fichier. Ne jamais écrire cette adresse en clair dans le code : elle
 * contient votre mot de passe. Elle doit toujours passer par une variable
 * d'environnement (sur Render : Environment → MONGODB_URI).
 *
 * Fichiers attendus dans le même dossier que ce script :
 *   - index.html   (le site)
 *   - package.json (déjà fourni, avec la dépendance "mongodb" incluse)
 */

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json({ limit: '6mb' })); // les photos de produits arrivent en base64 dans le JSON

// Sert index.html (et tout autre fichier posé dans ce même dossier)
// directement à la racine du site.
app.use(express.static(__dirname, { index: 'index.html' }));

const JWT_SECRET = process.env.JWT_SECRET || "change-moi-absolument-avant-de-publier";
const MONGODB_URI = process.env.MONGODB_URI || "";

if (!MONGODB_URI) {
  console.error("⚠️  MONGODB_URI n'est pas définie. Ajoutez-la dans les variables d'environnement (voir les instructions).");
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

async function start(){
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db('amarita');
  const sellers = db.collection('sellers');
  const products = db.collection('products');

  // Un même numéro de téléphone ne peut créer qu'un seul compte vendeur.
  await sellers.createIndex({ phone: 1 }, { unique: true });

  app.get('/api/health', (req, res) => {
    res.send('✅ Serveur Amarita en ligne — site, comptes vendeurs et PayTech actifs (base de données connectée).');
  });

  // ---------- Comptes vendeurs ----------
  app.post('/api/auth/signup', async (req, res) => {
    try {
      const { name, phone, password } = req.body;
      if (!name || !phone || !password) {
        return res.status(400).json({ error: "Nom, téléphone et mot de passe requis." });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: "Le mot de passe doit faire au moins 6 caractères." });
      }
      const existing = await sellers.findOne({ phone });
      if (existing) {
        return res.status(400).json({ error: "Un compte existe déjà avec ce numéro." });
      }
      const seller = {
        id: "s_" + Date.now(),
        name,
        phone,
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
      const { phone, password } = req.body;
      const seller = await sellers.findOne({ phone });
      if (!seller || !bcrypt.compareSync(password || '', seller.passwordHash)) {
        return res.status(401).json({ error: "Numéro ou mot de passe incorrect." });
      }
      const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '90d' });
      res.json({ token, seller: { id: seller.id, name: seller.name } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la connexion." });
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

  // ---------- Paiement PayTech ----------
  const PAYTECH_API_KEY = process.env.PAYTECH_API_KEY || "VOTRE_API_KEY";
  const PAYTECH_API_SECRET = process.env.PAYTECH_API_SECRET || "VOTRE_API_SECRET";
  const PAYTECH_ENV = process.env.PAYTECH_ENV || "test"; // "test" ou "prod"
  const BASE_URL = process.env.BASE_URL || "https://votre-domaine.sn";

  app.post('/api/paytech/request-payment', async (req, res) => {
    try {
      const { items, total } = req.body;
      if (!total || total <= 0) {
        return res.status(400).json({ error: "Panier vide ou montant invalide." });
      }
      const refCommand = "AMARITA_" + Date.now() + "_" + Math.floor(Math.random() * 10000);
      const commandName = (items || []).map(i => `${i.name} x${i.qty}`).join(", ").slice(0, 200) || "Commande Amarita";

      const payTechResponse = await fetch("https://paytech.sn/api/payment/request-payment", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API_KEY": PAYTECH_API_KEY,
          "API_SECRET": PAYTECH_API_SECRET
        },
        body: JSON.stringify({
          item_name: "Commande Amarita",
          item_price: total,
          currency: "XOF",
          ref_command: refCommand,
          command_name: commandName,
          ipn_url: `${BASE_URL}/api/paytech/ipn`,
          success_url: `${BASE_URL}/paiement-reussi`,
          cancel_url: `${BASE_URL}/paiement-annule`,
          env: PAYTECH_ENV,
          custom_field: JSON.stringify({ ref: refCommand })
        })
      });

      const data = await payTechResponse.json();
      if (data.redirect_url) {
        res.json({ redirect_url: data.redirect_url });
      } else {
        res.status(400).json({ error: data.errors || "Réponse PayTech invalide." });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Erreur serveur lors de la demande de paiement." });
    }
  });

  app.post('/api/paytech/ipn', (req, res) => {
    const { ref_command, item_price, payment_method, api_key_sha256, api_secret_sha256 } = req.body;
    const expectedKeyHash = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
    const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');
    if (api_key_sha256 === expectedKeyHash && api_secret_sha256 === expectedSecretHash) {
      console.log(`Paiement confirmé pour ${ref_command} : ${item_price} FCFA via ${payment_method}`);
      res.send("IPN OK");
    } else {
      res.status(400).send("IPN KO — signature invalide, requête ignorée");
    }
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Serveur Amarita démarré sur le port ${PORT}, connecté à MongoDB.`));
}

start().catch(err => {
  console.error("Impossible de démarrer le serveur :", err);
  process.exit(1);
});
