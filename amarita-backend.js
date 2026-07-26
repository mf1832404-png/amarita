/**
 * Serveur unique pour Amarita — site + backend ensemble
 * -------------------------------------------------------
 * Un seul serveur qui :
 *   1. Affiche le site (index.html) à l'adresse principale
 *   2. Gère les comptes vendeurs (inscription / connexion)
 *   3. Gère l'ajout, la liste et la suppression de produits par les vendeurs
 *   4. Gère le paiement par carte via PayTech
 *
 * Un seul déploiement à faire — plus besoin d'héberger le site (GitHub Pages)
 * et le backend séparément : les deux sont ici, ensemble.
 *
 * Installation :
 *   npm install
 *   JWT_SECRET=change-moi-absolument PAYTECH_API_KEY=xxx PAYTECH_API_SECRET=yyy BASE_URL=https://votre-domaine.sn npm start
 *
 * (nécessite Node.js 18 ou plus récent, pour que "fetch" soit disponible nativement)
 *
 * Fichiers attendus dans le même dossier que ce script :
 *   - index.html  (le site)
 *   - package.json (déjà fourni)
 *
 * Stockage des données :
 *   Les vendeurs et les produits sont enregistrés dans un simple fichier
 *   data.json à côté de ce script. Aucune base de données à installer pour
 *   démarrer. Attention : sur un hébergeur gratuit dont le disque n'est pas
 *   persistant (certains "free tier"), ce fichier peut être remis à zéro à
 *   chaque redéploiement. Pour un usage sérieux à plus grande échelle, il
 *   faudra migrer vers une vraie base de données plus tard — dites-le-moi
 *   le moment venu, je vous aiderai à faire la bascule.
 *
 * Une fois déployé, votre site est directement à l'adresse donnée par votre
 * hébergeur (ex: https://amarita.onrender.com) — rien d'autre à configurer
 * dans index.html, API_BASE et PAYTECH_ENDPOINT sont déjà en chemins relatifs.
 */

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Sert index.html (et tout autre fichier posé dans ce même dossier)
// directement à la racine du site.
app.use(express.static(__dirname, { index: 'index.html' }));

const JWT_SECRET = process.env.JWT_SECRET || "change-moi-absolument-avant-de-publier";
const DATA_FILE = path.join(__dirname, 'data.json');

// ---------- Petite base de données fichier ----------
function readData(){
  if (!fs.existsSync(DATA_FILE)) return { sellers: [], products: [] };
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function writeData(data){
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
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

app.get('/api/health', (req, res) => {
  res.send('✅ Serveur Amarita en ligne — site, comptes vendeurs et PayTech actifs.');
});

// ---------- Comptes vendeurs ----------
app.post('/api/auth/signup', (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password) {
    return res.status(400).json({ error: "Nom, téléphone et mot de passe requis." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Le mot de passe doit faire au moins 6 caractères." });
  }
  const data = readData();
  if (data.sellers.find(s => s.phone === phone)) {
    return res.status(400).json({ error: "Un compte existe déjà avec ce numéro." });
  }
  const seller = {
    id: "s_" + Date.now(),
    name,
    phone,
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: new Date().toISOString()
  };
  data.sellers.push(seller);
  writeData(data);
  const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, seller: { id: seller.id, name: seller.name } });
});

app.post('/api/auth/login', (req, res) => {
  const { phone, password } = req.body;
  const data = readData();
  const seller = data.sellers.find(s => s.phone === phone);
  if (!seller || !bcrypt.compareSync(password || '', seller.passwordHash)) {
    return res.status(401).json({ error: "Numéro ou mot de passe incorrect." });
  }
  const token = jwt.sign({ id: seller.id, name: seller.name }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, seller: { id: seller.id, name: seller.name } });
});

// ---------- Produits ----------
app.get('/api/products', (req, res) => {
  const data = readData();
  res.json({ products: data.products });
});

app.post('/api/products', authMiddleware, (req, res) => {
  const { name, price, cat, icon } = req.body;
  const allowedCats = ["mode", "beaute", "epicerie", "artisanat"];
  if (!name || !price || !allowedCats.includes(cat)) {
    return res.status(400).json({ error: "Nom, prix et catégorie valide requis." });
  }
  const data = readData();
  const product = {
    id: "p_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
    sellerId: req.seller.id,
    sellerName: req.seller.name,
    name,
    price: Number(price),
    cat,
    icon: icon || "🛍️",
    createdAt: new Date().toISOString()
  };
  data.products.push(product);
  writeData(data);
  res.json({ product });
});

app.get('/api/products/mine', authMiddleware, (req, res) => {
  const data = readData();
  res.json({ products: data.products.filter(p => p.sellerId === req.seller.id) });
});

app.delete('/api/products/:id', authMiddleware, (req, res) => {
  const data = readData();
  const product = data.products.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: "Produit introuvable." });
  if (product.sellerId !== req.seller.id) {
    return res.status(403).json({ error: "Ce n'est pas l'un de vos produits." });
  }
  data.products = data.products.filter(p => p.id !== req.params.id);
  writeData(data);
  res.json({ success: true });
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
      // TODO : enregistrez ici refCommand + total dans data.json avec un
      // statut "en attente", pour pouvoir le retrouver quand l'IPN arrivera.
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
app.listen(PORT, () => console.log(`Serveur Amarita démarré sur le port ${PORT}`));
