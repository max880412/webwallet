// server.js
const express = require('express');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const axios = require('axios');
const { check, validationResult } = require('express-validator');
const { ethers } = require('ethers');
const http = require('http');
const Parser = require('rss-parser');
const parser = new Parser();
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Configurar archivos estáticos y body-parser
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configurar EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configurar sesiones con cookie persistente (24 hrs)
app.use(session({
  secret: 'your-secret-key', // Cambia esto en producción
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

// Hacer que req.session esté disponible en las vistas
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// Conexión a la base de datos SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) console.error(err);
  else console.log('Conectado a SQLite.');
});

// Crear tablas si no existen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT,
    lastName TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    returnWallet TEXT,
    isAdmin INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    walletAddress TEXT,
    privateKey TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    walletId INTEGER,
    txHash TEXT,
    fromAddress TEXT,
    toAddress TEXT,
    value TEXT,
    direction TEXT,  -- 'deposit' o 'withdraw'
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(walletId) REFERENCES wallets(id)
  )`);
});

// Configurar Socket.IO para notificar a los clientes en tiempo real
io.on('connection', (socket) => {
  console.log('Cliente conectado: ' + socket.id);
});

// Middleware de autenticación y administrador
function isAuthenticated(req, res, next) {
  if (req.session.userId) next();
  else res.redirect('/login');
}
function isAdmin(req, res, next) {
  if (req.session.isAdmin) next();
  else res.status(403).send("Acceso denegado.");
}

// Función para validar una dirección BEP20 (similar a Ethereum)
function isValidBEP20(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/* ============================
   RUTAS
============================ */

// Dashboard: se crea la wallet si no existe; se obtienen noticias y actividad
app.get('/', isAuthenticated, async (req, res) => {
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], async (err, wallet) => {
    if (err) console.error(err);
    let walletData;
    if (!wallet) {
      // Crear wallet usando ethers
      const newWallet = ethers.Wallet.createRandom();
      db.run(`INSERT INTO wallets (userId, walletAddress, privateKey) VALUES (?, ?, ?)`,
        [req.session.userId, newWallet.address, newWallet.privateKey],
        function(err) {
          if (err) console.error(err);
        });
      walletData = { walletAddress: newWallet.address };
    } else {
      walletData = { walletAddress: wallet.walletAddress };
    }

    // Obtener noticias desde un feed RSS (ejemplo: NYT Technology)
    let news = [];
    try {
      const feed = await parser.parseURL('https://rss.nytimes.com/services/xml/rss/nyt/Technology.xml');
      news = feed.items; // Arreglo de artículos
    } catch (error) {
      console.error('Error al parsear RSS:', error);
    }

    // Obtener actividad reciente (últimas 10 transacciones para el wallet)
    if (wallet) {
      db.all(`SELECT * FROM transactions WHERE walletId = ? ORDER BY createdAt DESC LIMIT 10`, [wallet.id], (err, rows) => {
        if (err) console.error(err);
        const activities = rows || [];
        res.render('dashboard', { wallet: walletData, news, activities });
      });
    } else {
      res.render('dashboard', { wallet: walletData, news, activities: [] });
    }
  });
});

// Confirmar depósito: se registra la transacción y se emite un evento vía WebSocket
app.post('/confirm-deposit', isAuthenticated, (req, res) => {
  const { txHash, fromAddress, value } = req.body;
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
    if (err || !wallet) return res.status(400).json({ error: "Wallet no encontrada" });
    db.run(`INSERT INTO transactions (walletId, txHash, fromAddress, toAddress, value, direction) VALUES (?, ?, ?, ?, ?, 'deposit')`,
      [wallet.id, txHash, fromAddress, wallet.walletAddress, value],
      function(err) {
        if (err) return res.status(500).json({ error: "Error al registrar depósito" });
        const depositData = {
          email: req.session.email || 'usuario',
          txHash,
          fromAddress,
          value,
          wallet: wallet.walletAddress,
          date: new Date().toLocaleString()
        };
        // Emitir evento de depósito confirmado
        io.emit('depositConfirmed', depositData);
        res.json({ success: true });
      });
  });
});

// Endpoint para obtener actividad reciente (útil para polling si se requiere)
app.get('/activities', isAuthenticated, (req, res) => {
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
    if (err || !wallet) return res.json([]);
    db.all(`SELECT * FROM transactions WHERE walletId = ? ORDER BY createdAt DESC LIMIT 10`, [wallet.id], (err, rows) => {
      if (err) return res.json([]);
      res.json(rows);
    });
  });
});

// Perfil: mostrar datos y permitir actualizar (cambio de contraseña y return wallet)
app.get('/profile', isAuthenticated, (req, res) => {
  db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect('/');
    res.render('profile', { user, errors: [] });
  });
});
app.post('/profile', isAuthenticated, [
  check('newPassword').optional({ checkFalsy: true }).isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres.'),
  check('returnWallet').optional({ checkFalsy: true }).custom(value => {
    if (!isValidBEP20(value)) {
      throw new Error('La return wallet debe ser una wallet BEP20 válida.');
    }
    return true;
  })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('profile', { user: req.body, errors: errors.array() });
  }
  const { newPassword, returnWallet } = req.body;
  if (newPassword) {
    bcrypt.hash(newPassword, 10, (err, hash) => {
      if (err) {
        return res.render('profile', { user: req.body, errors: [{ msg: 'Error al actualizar la contraseña.' }] });
      }
      db.run(`UPDATE users SET password = ?, returnWallet = ? WHERE id = ?`, [hash, returnWallet, req.session.userId], function(err) {
        if (err) return res.render('profile', { user: req.body, errors: [{ msg: 'Error al actualizar los datos.' }] });
        res.redirect('/profile');
      });
    });
  } else {
    db.run(`UPDATE users SET returnWallet = ? WHERE id = ?`, [returnWallet, req.session.userId], function(err) {
      if (err) return res.render('profile', { user: req.body, errors: [{ msg: 'Error al actualizar los datos.' }] });
      res.redirect('/profile');
    });
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});
app.post('/login', [
  check('email').isEmail().withMessage('Correo inválido.').normalizeEmail(),
  check('password').trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render('login', { error: 'Datos inválidos.' });
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user) return res.render('login', { error: 'Credenciales inválidas.' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        req.session.userId = user.id;
        req.session.isAdmin = user.isAdmin;
        req.session.email = user.email;
        res.redirect('/');
      } else {
        res.render('login', { error: 'Credenciales inválidas.' });
      }
    });
  });
});

// Registro
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});
app.post('/register', [
  check('firstName').trim().escape(),
  check('lastName').trim().escape(),
  check('email').isEmail().withMessage('Correo inválido.').normalizeEmail(),
  check('phone').trim().escape(),
  check('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render('register', { error: errors.array()[0].msg });
  const { firstName, lastName, email, phone, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.render('register', { error: 'Error durante el registro.' });
    const stmt = db.prepare(`INSERT INTO users (firstName, lastName, email, phone, password) VALUES (?, ?, ?, ?, ?)`);
    stmt.run(firstName, lastName, email, phone, hash, function(err) {
      if (err) return res.render('register', { error: 'El correo ya está registrado o error en el registro.' });
      res.redirect('/login');
    });
    stmt.finalize();
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Panel de Administración (solo para administradores)
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  db.all(`SELECT u.*, w.walletAddress, w.privateKey FROM users u LEFT JOIN wallets w ON u.id = w.userId`, (err, users) => {
    if (err) return res.send("Error al cargar el panel de admin.");
    res.render('admin', { users });
  });
});

// Iniciar el servidor usando el objeto "server" de http
server.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
