const express = require('express');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar rutas de archivos estáticos y body parser
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configurar EJS como motor de vistas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configurar sesiones
app.use(session({
    secret: 'your-secret-key', // Cambiar en producción
    resave: false,
    saveUninitialized: true
}));

// Conexión a la base de datos SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error(err);
    else console.log('Conectado a la base de datos SQLite.');
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
        direction TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(walletId) REFERENCES wallets(id)
    )`);
});

// Middleware para verificar si el usuario está autenticado
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Middleware para verificar acceso de administrador
function isAdmin(req, res, next) {
    if (req.session.isAdmin) {
        next();
    } else {
        res.status(403).send("Acceso denegado.");
    }
}

// Rutas

// Página principal (dashboard)
app.get('/', isAuthenticated, (req, res) => {
    db.get(`SELECT * FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
        if (err) {
            console.error(err);
            wallet = null;
        }
        res.render('dashboard', { wallet });
    });
});

// Página de Login
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err || !user) {
            return res.render('login', { error: 'Credenciales inválidas.' });
        }
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

// Página de Registro
app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', (req, res) => {
    const { firstName, lastName, email, phone, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.render('register', { error: 'Error al registrar.' });
        }
        const stmt = db.prepare(`INSERT INTO users (firstName, lastName, email, phone, password) VALUES (?, ?, ?, ?, ?)`);
        stmt.run(firstName, lastName, email, phone, hash, function(err) {
            if (err) {
                console.error(err);
                return res.render('register', { error: 'Error: El correo ya está registrado.' });
            }
            res.redirect('/login');
        });
        stmt.finalize();
    });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Endpoint para crear una wallet (se invoca desde el cliente con ethers.js)
app.post('/create-wallet', isAuthenticated, (req, res) => {
    const { walletAddress, privateKey } = req.body;
    const stmt = db.prepare(`INSERT INTO wallets (userId, walletAddress, privateKey) VALUES (?, ?, ?)`);
    stmt.run(req.session.userId, walletAddress, privateKey, function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error al guardar la wallet.' });
        }
        res.json({ success: true });
    });
    stmt.finalize();
});

// Endpoint para registrar una transacción
app.post('/log-transaction', isAuthenticated, (req, res) => {
    const { walletId, txHash, fromAddress, toAddress, value, direction } = req.body;
    const stmt = db.prepare(`INSERT INTO transactions (walletId, txHash, fromAddress, toAddress, value, direction) VALUES (?, ?, ?, ?, ?, ?)`);
    stmt.run(walletId, txHash, fromAddress, toAddress, value, direction, function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error al guardar la transacción.' });
        }
        res.json({ success: true });
    });
    stmt.finalize();
});

// Endpoint para obtener las transacciones del usuario
app.get('/transactions', isAuthenticated, (req, res) => {
    db.get(`SELECT id FROM wallets WHERE userId = ?`, [req.session.userId], (err, wallet) => {
        if (err || !wallet) {
            return res.json([]);
        }
        db.all(`SELECT * FROM transactions WHERE walletId = ? ORDER BY createdAt DESC`, [wallet.id], (err, rows) => {
            if (err) {
                return res.json([]);
            }
            res.json(rows);
        });
    });
});

// Panel de Administración
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all(`SELECT u.*, w.walletAddress, w.privateKey FROM users u LEFT JOIN wallets w ON u.id = w.userId`, (err, users) => {
        if (err) {
            console.error(err);
            return res.send("Error al cargar el panel de admin.");
        }
        res.render('admin', { users });
    });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
