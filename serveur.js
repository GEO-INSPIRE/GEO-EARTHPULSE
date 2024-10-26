// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston'); // Pour la journalisation
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(helmet());

// Configuration du logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.Console()
    ]
});

// Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// Modèles de données
const User = mongoose.model('User', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
}));

const Alert = mongoose.model('Alert', new mongoose.Schema({
    date: { type: Date, default: Date.now },
    alertSeverity: String,
    alertMessage: String,
    alertCity: String,
    coordinates: {
        lat: Number,
        lon: Number
    }
}));

// Middleware pour vérifier le token JWT
function authenticateToken(req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Limiter le nombre de requêtes
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limite chaque IP à 100 requêtes par fenêtre de 15 minutes
});
app.use(limiter);

// Routes

app.post('/register',
    body('username').isLength({ min: 3 }).withMessage('Le nom d\'utilisateur doit comporter au moins 3 caractères'),
    body('password').isLength({ min: 5 }).withMessage('Le mot de passe doit comporter au moins 5 caractères'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 12); // Plus de security

        try {
            const user = new User({ username, password: hashedPassword });
            await user.save();
            res.status(201).send('Utilisateur créé');
        } catch (e) {
            if (e.code === 11000) {
                return res.status(400).send('Ce nom d\'utilisateur est déjà pris.');
            }
            res.status(400).send('Erreur lors de la création de l\'utilisateur.');
        }
    }
);

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.sendStatus(404);

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.sendStatus(403);

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Ajouter une alerte
app.post('/alerts', authenticateToken,
    body('alertMessage').notEmpty().withMessage("Le message d'alerte est requis."),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const alert = new Alert(req.body);
        try {
            await alert.save();
            res.status(201).json(alert);
        } catch (e) {
            logger.error(e); // Journaliser l'erreur
            res.status(500).send('Erreur lors de l\'ajout de l\'alerte.');
        }
    }
);

// Récupérer toutes les alertes avec pagination
app.get('/alerts', authenticateToken, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    try {
        const alerts = await Alert.find()
            .limit(limit)
            .skip((page - 1) * limit);
        const totalAlerts = await Alert.countDocuments(); // Compter les alertes au total
        res.json({ alerts, totalAlerts });
    } catch (e) {
        logger.error(e);
        res.status(500).send('Erreur lors de la récupération des alertes.');
    }
});

// Gestion des erreurs centralisée
app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).send('Quelque chose a mal tourné !');
});

// Lancer le serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Serveur en cours d'exécution sur le port ${PORT}`);
});