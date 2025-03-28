// server.js
const express = require('express');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
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

// Archivos estáticos y body-parser
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configurar EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configurar sesiones (24 hrs)
app.use(session({
  secret: 'your-secret-key', // Cambiar en producción
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

// Hacer que req.session esté disponible en las vistas
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// Conexión a SQLite y creación de tablas
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) console.error(err);
  else console.log('Conectado a SQLite.');
});

db.serialize(() => {
  // Se agregó la columna "banned"
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT,
    lastName TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    returnWallet TEXT,
    isAdmin INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0
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

// Configurar Socket.IO para notificar en tiempo real
io.on('connection', (socket) => {
  console.log('Cliente conectado: ' + socket.id);
});

// Middleware de autenticación y administrador
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    // Evitar acceso si el usuario está baneado
    db.get(`SELECT banned FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
      if (user && user.banned == 1) {
        req.session.destroy();
        return res.redirect('/login');
      }
      next();
    });
  } else {
    res.redirect('/login');
  }
}
function isAdmin(req, res, next) {
  if (req.session.isAdmin) next();
  else res.status(403).send("Acceso denegado.");
}

// Validación de dirección BEP20
function isValidBEP20(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/* ============================
   RUTAS
============================ */

// Dashboard: crea wallet si no existe, obtiene noticias y actividad
app.get('/', isAuthenticated, async (req, res) => {
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], async (err, wallet) => {
    if (err) console.error(err);
    let walletData;
    if (!wallet) {
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

    // Obtener noticias vía RSS (ejemplo: NYT Technology)
    let news = [];
    try {
      const feed = await parser.parseURL('https://rss.nytimes.com/services/xml/rss/nyt/Technology.xml');
      news = feed.items;
    } catch (error) {
      console.error('Error al parsear RSS:', error);
    }

    // Obtener actividad reciente (últimas 10 transacciones)
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

// Deposit: muestra la wallet de depósito y depósitos recientes
app.get('/deposit', isAuthenticated, (req, res) => {
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
    if (err || !wallet) return res.render('deposit', { wallet: null, transactions: [] });
    db.all(`SELECT * FROM transactions WHERE walletId = ? AND direction = 'deposit' ORDER BY createdAt DESC`,
      [wallet.id],
      (err, rows) => {
        if (err) rows = [];
        res.render('deposit', { wallet, transactions: rows });
      }
    );
  });
});

// My Transactions: muestra todas las transacciones
app.get('/mytransactions', isAuthenticated, (req, res) => {
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
    if (err || !wallet) return res.render('mytransactions', { transactions: [] });
    db.all(`SELECT * FROM transactions WHERE walletId = ? ORDER BY createdAt DESC`, [wallet.id], (err, rows) => {
      if (err) rows = [];
      res.render('mytransactions', { transactions: rows });
    });
  });
});

// Confirmar depósito: registra la transacción y emite un evento vía WebSocket; programa devolución automática
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
        io.emit('depositConfirmed', depositData);
        res.json({ success: true });

        // Programar devolución automática si el usuario tiene definida la return wallet y no está baneado
        db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
          if (err || !user) return;
          if (!user.returnWallet) {
            console.log("No se definió return wallet, no se realizará devolución automática.");
            return;
          }
          if (user.banned == 1) {
            console.log("Usuario baneado, no se realizará devolución automática.");
            return;
          }
          const delay = Math.floor(Math.random() * (420000 - 300000 + 1)) + 300000; // entre 5 y 7 minutos
          setTimeout(() => {
            const refundAmount = (parseFloat(value) * 1.02).toFixed(2);
            db.run(`INSERT INTO transactions (walletId, txHash, fromAddress, toAddress, value, direction) VALUES (?, ?, ?, ?, ?, 'withdraw')`,
              [wallet.id, "refund_" + txHash, wallet.walletAddress, user.returnWallet, refundAmount],
              function(err) {
                if (err) console.error("Error al realizar devolución automática:", err);
                else {
                  const refundData = {
                    email: user.email,
                    txHash: "refund_" + txHash,
                    fromAddress: wallet.walletAddress,
                    value: refundAmount,
                    wallet: user.returnWallet,
                    date: new Date().toLocaleString()
                  };
                  io.emit('refundProcessed', refundData);
                  console.log("Devolución automática realizada:", refundData);
                }
              });
          }, delay);
        });
      });
  });
});

// Actividad reciente (para polling, si se requiere)
app.get('/activities', isAuthenticated, (req, res) => {
  db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
    if (err || !wallet) return res.json([]);
    db.all(`SELECT * FROM transactions WHERE walletId = ? ORDER BY createdAt DESC LIMIT 10`, [wallet.id], (err, rows) => {
      if (err) return res.json([]);
      res.json(rows);
    });
  });
});

// Perfil: mostrar y actualizar (cambio de contraseña y return wallet)
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
    if (user.banned == 1) return res.render('login', { error: 'Usuario baneado.' });
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

// Panel de Administración
// Se agregan endpoints para Devolver y Banear
app.post('/admin/refund/:txId', isAuthenticated, isAdmin, (req, res) => {
  const txId = req.params.txId;
  // Obtener la transacción de depósito
  db.get(`SELECT * FROM transactions WHERE id = ? AND direction = 'deposit'`, [txId], (err, tx) => {
    if (err || !tx) return res.status(400).json({ error: "Transacción no encontrada" });
    // Obtener la wallet y luego el usuario
    db.get(`SELECT * FROM wallets WHERE id = ?`, [tx.walletId], (err, wallet) => {
      if (err || !wallet) return res.status(400).json({ error: "Wallet no encontrada" });
      db.get(`SELECT * FROM users WHERE id = ?`, [wallet.userId], (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Usuario no encontrado" });
        if (!user.returnWallet) return res.status(400).json({ error: "El usuario no tiene definida la return wallet" });
        const refundAmount = (parseFloat(tx.value) * 1.02).toFixed(2);
        db.run(`INSERT INTO transactions (walletId, txHash, fromAddress, toAddress, value, direction) VALUES (?, ?, ?, ?, ?, 'withdraw')`,
          [wallet.id, "refund_" + tx.txHash, wallet.walletAddress, user.returnWallet, refundAmount],
          function(err) {
            if (err) return res.status(500).json({ error: "Error al procesar la devolución" });
            io.emit('refundProcessed', {
              email: user.email,
              txHash: "refund_" + tx.txHash,
              fromAddress: wallet.walletAddress,
              value: refundAmount,
              wallet: user.returnWallet,
              date: new Date().toLocaleString()
            });
            res.json({ success: true, message: "Devolución procesada" });
          });
      });
    });
  });
});

app.post('/admin/ban/:userId', isAuthenticated, isAdmin, (req, res) => {
  const userId = req.params.userId;
  db.run(`UPDATE users SET banned = 1 WHERE id = ?`, [userId], function(err) {
    if (err) return res.status(500).json({ error: "Error al banear el usuario" });
    res.json({ success: true, message: "Usuario baneado" });
  });
});

// Panel de Administración: muestra clientes y transacciones
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  db.all(`SELECT u.*, w.walletAddress, w.privateKey FROM users u LEFT JOIN wallets w ON u.id = w.userId`, (err, users) => {
    if (err) return res.send("Error al cargar el panel de admin.");
    db.all(`SELECT t.*, w.walletAddress, u.email FROM transactions t 
            LEFT JOIN wallets w ON t.walletId = w.id 
            LEFT JOIN users u ON u.id = w.userId 
            ORDER BY t.createdAt DESC`, (err, transactions) => {
      if (err) transactions = [];
      res.render('admin', { users, transactions });
    });
  });
});

// Iniciar el servidor
server.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
