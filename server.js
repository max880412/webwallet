const express = require('express');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const axios = require('axios');
const { check, validationResult } = require('express-validator');
const { ethers } = require('ethers');

const app = express();
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

// Conexión a la base de datos SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error(err);
    else console.log('Conectado a SQLite.');
});

// Crear tablas (se incluye returnWallet en users)
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
        direction TEXT,  -- 'inbound' o 'outbound'
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(walletId) REFERENCES wallets(id)
    )`);
});

// Middleware para verificar autenticación y admin
function isAuthenticated(req, res, next) {
    if (req.session.userId) next();
    else res.redirect('/login');
}
function isAdmin(req, res, next) {
    if (req.session.isAdmin) next();
    else res.status(403).send("Acceso denegado.");
}

// Validación de dirección BEP20 (similar a una dirección Ethereum)
function isValidBEP20(address) {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
}

// Rutas

// Dashboard: Si el usuario no tiene wallet, se crea y guarda; se muestra solo la dirección (sin private key)
app.get('/', isAuthenticated, (req, res) => {
    db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
        if (err) console.error(err);
        if (!wallet) {
            // Crear wallet con ethers
            const newWallet = ethers.Wallet.createRandom();
            db.run(`INSERT INTO wallets (userId, walletAddress, privateKey) VALUES (?, ?, ?)`,
                [req.session.userId, newWallet.address, newWallet.privateKey],
                function(err) {
                    if (err) console.error(err);
                    // Enviamos solo la dirección a la vista
                    res.render('dashboard', { wallet: { walletAddress: newWallet.address } });
                });
        } else {
            res.render('dashboard', { wallet: { walletAddress: wallet.walletAddress } });
        }
    });
});

// My Transactions: Muestra las transacciones (todas) relacionadas con la wallet asignada
app.get('/mytransactions', isAuthenticated, (req, res) => {
    db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
        if (err || !wallet) return res.render('mytransactions', { transactions: [] });
        db.all(`SELECT * FROM transactions WHERE walletId = ? ORDER BY createdAt DESC`, [wallet.id], (err, rows) => {
            if (err) rows = [];
            res.render('mytransactions', { transactions: rows });
        });
    });
});

// Deposit: Muestra la wallet y las instrucciones para depositar; lista las transacciones entrantes
app.get('/deposit', isAuthenticated, (req, res) => {
    db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
        if (err || !wallet) return res.render('deposit', { wallet: null, transactions: [] });
        db.all(`SELECT * FROM transactions WHERE walletId = ? AND direction = 'inbound' ORDER BY createdAt DESC`, [wallet.id], (err, rows) => {
            if (err) rows = [];
            res.render('deposit', { wallet, transactions: rows });
        });
    });
});

// Perfil: Permite al usuario cambiar contraseña y actualizar el campo returnWallet (se valida que sea una dirección BEP20 válida)
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
            throw new Error('La dirección de return wallet debe ser una wallet BEP20 válida.');
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

// Login (con sanitización)
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
                res.redirect('/');
            } else {
                res.render('login', { error: 'Credenciales inválidas.' });
            }
        });
    });
});

// Registro (con sanitización)
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
        if (err) return res.render('register', { error: 'Error al registrar.' });
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

// Ruta del panel de administración (ya existente)
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all(`SELECT u.*, w.walletAddress, w.privateKey FROM users u LEFT JOIN wallets w ON u.id = w.userId`, (err, users) => {
        if (err) return res.send("Error al cargar el panel de admin.");
        res.render('admin', { users });
    });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
