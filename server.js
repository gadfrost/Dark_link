const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const webpush = require('web-push');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

// Clé secrète JWT
const JWT_SECRET = process.env.JWT_SECRET || 'dark_link_ultra_secure_secret_key_2026_!@#$%^&*';

// Web Push VAPID Keys
const publicVapidKey = process.env.VAPID_PUBLIC_KEY || 'BGMZGsYg4HvZK_ozhUgWtZyktzvxf7jNDLoc4Thg_5xOnP8TwrynskG6udipXfD0kq7p93ztiAg7A0HoLwl4_qM';
const privateVapidKey = process.env.VAPID_PRIVATE_KEY || 'ssCe6VI7VIWYUN4q02t-CXlV19s2J_ivjcsJBvC3hfQ';
webpush.setVapidDetails('mailto:contact@darklink.local', publicVapidKey, privateVapidKey);

// Middleware de sécurité pour les en-têtes HTTP
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// Middleware standard
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Assurer l'existence du dossier uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
app.use('/uploads', express.static(uploadDir));

// Rate Limiter pour l'authentification (Anti-Brute Force)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Trop de tentatives de connexion. Veuillez réessayer dans 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Configuration Multer sécurisée
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, 'darklink_' + uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedMimeTypes = [
        'image/jpeg', 'image/png', 'image/webp', 'image/gif',
        'video/mp4', 'video/webm', 'video/quicktime',
        'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/mp4'
    ];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.mp4', '.webm', '.mov', '.mp3', '.ogg', '.wav'];
    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedMimeTypes.includes(file.mimetype) && allowedExtensions.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('Format de fichier non autorisé. Seules les images et vidéos sont acceptées.'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 40 * 1024 * 1024 }
});

// -------------------------------------------------------------
// CONFIGURATION POSTGRESQL (RENDER DATABASE_URL COMPATIBLE)
// -------------------------------------------------------------
const poolConfig = process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    }
    : {
        host: process.env.PGHOST || 'localhost',
        port: Number(process.env.PGPORT) || 5432,
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD || 'postgres',
        database: process.env.PGDATABASE || 'dark_link_db'
    };

const db = new Pool(poolConfig);

// Helper pour exécuter des requêtes renvoyant des lignes
const queryDB = async (sql, params = []) => {
    const result = await db.query(sql, params);
    return result.rows;
};

// -------------------------------------------------------------
// INITIALISATION AUTOMATIQUE DU SCHÉMA POSTGRESQL AU DÉMARRAGE
// -------------------------------------------------------------
async function initDatabase() {
    try {
        console.log('📦 Vérification et création automatique des tables PostgreSQL...');

        // 1. Table users
        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                phone VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                profile_pic TEXT,
                status_message VARCHAR(255) DEFAULT 'Salut ! J''utilise Dark Link.',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 2. Table friendships
        await db.query(`
            CREATE TABLE IF NOT EXISTS friendships (
                id SERIAL PRIMARY KEY,
                sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 3. Table groups
        await db.query(`
            CREATE TABLE IF NOT EXISTS "groups" (
                id SERIAL PRIMARY KEY,
                name VARCHAR(150) NOT NULL,
                group_pic TEXT,
                created_by INT REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 4. Table group_members
        await db.query(`
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INT NOT NULL REFERENCES "groups"(id) ON DELETE CASCADE,
                user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role VARCHAR(50) DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, user_id)
            )
        `);

        // 5. Table messages
        await db.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
                group_id INT REFERENCES "groups"(id) ON DELETE CASCADE,
                content TEXT,
                media_type VARCHAR(50) DEFAULT 'text',
                is_read BOOLEAN DEFAULT FALSE,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 6. Table statuses
        await db.query(`
            CREATE TABLE IF NOT EXISTS statuses (
                id SERIAL PRIMARY KEY,
                user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT,
                media_url TEXT,
                media_type VARCHAR(50) DEFAULT 'text',
                bg_color VARCHAR(120) DEFAULT 'linear-gradient(135deg, #1a6eff, #0d3b8f)',
                duration_hours INT DEFAULT 24,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        `);

        // 7. Table status_views
        await db.query(`
            CREATE TABLE IF NOT EXISTS status_views (
                id SERIAL PRIMARY KEY,
                status_id INT NOT NULL REFERENCES statuses(id) ON DELETE CASCADE,
                viewer_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT unique_status_viewer UNIQUE (status_id, viewer_id)
            )
        `);

        // 8. Table push_subscriptions
        await db.query(`
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id SERIAL PRIMARY KEY,
                user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                subscription JSONB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ Base de données PostgreSQL initialisée avec succès.');
    } catch (err) {
        console.error('⚠️ Avertissement lors de l\'initialisation des tables PostgreSQL:', err.message);
    }
}

// Middleware d'authentification JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = (authHeader && authHeader.startsWith('Bearer ')) 
        ? authHeader.split(' ')[1] 
        : (req.query.token || req.headers['x-auth-token']);

    if (!token) {
        if (req.query.userId || req.body.userId || req.params.userId) {
            req.user = { id: Number(req.query.userId || req.body.userId || req.params.userId) };
            return next();
        }
        return res.status(401).json({ error: 'Accès non autorisé. Token manquant.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (req.query.userId || req.body.userId) {
                req.user = { id: Number(req.query.userId || req.body.userId) };
                return next();
            }
            return res.status(403).json({ error: 'Session expirée ou token invalide.' });
        }
        req.user = user;
        next();
    });
}

// Tracking de présence en ligne
const onlineUsers = new Map();
function isUserOnline(userId) {
    const sockets = onlineUsers.get(Number(userId));
    return Boolean(sockets && sockets.size > 0);
}

// -------------------------------------------------------------
// ROUTES D'AUTHENTIFICATION ET WEB PUSH
// -------------------------------------------------------------

app.get('/api/vapidPublicKey', (req, res) => {
    res.json({ publicKey: publicVapidKey });
});

app.post('/api/subscribe', authenticateToken, async (req, res) => {
    const subscription = req.body;
    const userId = req.user.id;

    try {
        await db.query(
            'INSERT INTO push_subscriptions (user_id, subscription) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [userId, subscription]
        );
        res.status(201).json({ message: 'Abonnement Push enregistré avec succès.' });
    } catch (err) {
        console.error('Erreur lors de l\'enregistrement de l\'abonnement push:', err);
        res.status(500).json({ error: 'Erreur serveur.' });
    }
});

// Inscription
app.post('/register', authLimiter, async (req, res) => {
    const { username, email, phone, password } = req.body;
    if (!username || !email || !phone || !password) {
        return res.status(400).json({ error: 'Tous les champs sont obligatoires.' });
    }

    if (username.length < 3 || password.length < 4) {
        return res.status(400).json({ error: 'Nom d\'utilisateur ou mot de passe trop court.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `
            INSERT INTO users (username, email, phone, password, status_message) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id
        `;
        const result = await db.query(sql, [username.trim(), email.trim(), phone.trim(), hashedPassword, 'Salut ! J\'utilise Dark Link.']);
        const userId = result.rows[0].id;
        const token = jwt.sign({ id: userId, username: username.trim(), email: email.trim() }, JWT_SECRET, { expiresIn: '14d' });

        res.status(201).json({ 
            message: 'Utilisateur créé avec succès !',
            userId,
            token
        });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Cet email, nom d\'utilisateur ou numéro de téléphone est déjà utilisé.' });
        }
        console.error('Erreur inscription:', err);
        res.status(500).json({ error: 'Erreur lors de l\'enregistrement.' });
    }
});

// Connexion
app.post('/login', authLimiter, async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
        return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
    }

    try {
        const sql = 'SELECT * FROM users WHERE email = $1 OR phone = $2 LIMIT 1';
        const result = await db.query(sql, [identifier.trim(), identifier.trim()]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Identifiant ou mot de passe incorrect.' });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
        }

        const token = jwt.sign({
            id: user.id,
            username: user.username,
            email: user.email
        }, JWT_SECRET, { expiresIn: '14d' });

        res.json({
            message: 'Connexion réussie',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                phone: user.phone,
                profile_pic: user.profile_pic,
                status_message: user.status_message
            }
        });
    } catch (err) {
        console.error('Erreur connexion:', err);
        res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
    }
});

// -------------------------------------------------------------
// ROUTES UTILISATEURS & PROFIL
// -------------------------------------------------------------

app.get('/api/users/me', authenticateToken, async (req, res) => {
    const userId = req.user.id || req.query.userId;
    if (!userId) return res.status(400).json({ error: 'userId requis' });

    try {
        const result = await db.query(
            'SELECT id, username, email, phone, profile_pic, status_message, created_at FROM users WHERE id = $1',
            [userId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
    const userId = req.user.id || req.body.userId;
    const { username, status_message } = req.body;
    if (!userId || !username) {
        return res.status(400).json({ error: 'userId et username requis.' });
    }

    try {
        const sql = 'UPDATE users SET username = $1, status_message = $2 WHERE id = $3';
        await db.query(sql, [username.trim(), status_message ? status_message.trim() : '', userId]);
        res.json({ message: 'Profil mis à jour avec succès.' });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Ce nom d\'utilisateur est déjà pris.' });
        }
        res.status(500).json({ error: 'Erreur lors de la mise à jour.' });
    }
});

app.post('/api/upload/avatar', authenticateToken, (req, res) => {
    upload.single('avatar')(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ error: err.message || 'Erreur lors du téléversement.' });
        }
        if (!req.file) return res.status(400).json({ error: 'Aucun fichier uploadé.' });

        const userId = req.user.id || req.body.userId;
        const avatarUrl = '/uploads/' + req.file.filename;

        try {
            await db.query('UPDATE users SET profile_pic = $1 WHERE id = $2', [avatarUrl, userId]);
            res.json({ message: 'Avatar mis à jour', avatarUrl });
        } catch (dbErr) {
            res.status(500).json({ error: 'Erreur base de données.' });
        }
    });
});

app.post('/api/upload/media', (req, res) => {
    upload.single('media')(req, res, (err) => {
        if (err) {
            return res.status(400).json({ error: err.message || 'Format de fichier non autorisé.' });
        }
        if (!req.file) return res.status(400).json({ error: 'Aucun fichier envoyé.' });

        const mediaUrl = '/uploads/' + req.file.filename;
        let mediaType = 'image';
        const mime = req.file.mimetype || '';
        if (mime.startsWith('video/')) mediaType = 'video';
        else if (mime.startsWith('audio/')) mediaType = 'audio';

        res.json({
            mediaUrl,
            mediaType,
            originalName: path.basename(req.file.originalname),
            size: req.file.size
        });
    });
});

app.get('/api/download/:filename', (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(uploadDir, filename);

    if (!filePath.startsWith(uploadDir) || !fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Fichier non trouvé.' });
    }
    res.download(filePath, filename);
});

// -------------------------------------------------------------
// ROUTES AMIS & RECHERCHE
// -------------------------------------------------------------

app.get('/api/users/search', authenticateToken, async (req, res) => {
    const q = req.query.q ? req.query.q.trim() : '';
    const userId = req.user.id || req.query.userId;
    if (!q || !userId) return res.json([]);

    try {
        const sql = `
            SELECT u.id, u.username, u.email, u.phone, u.profile_pic, u.status_message,
                f.status AS friendship_status,
                f.sender_id AS friendship_sender
            FROM users u
            LEFT JOIN friendships f 
                ON ((f.sender_id = $1 AND f.receiver_id = u.id) OR (f.sender_id = u.id AND f.receiver_id = $2))
            WHERE u.id != $3 AND (u.username ILIKE $4 OR u.email ILIKE $5 OR u.phone ILIKE $6)
            LIMIT 20
        `;
        const searchPattern = `%${q}%`;
        const result = await db.query(sql, [userId, userId, userId, searchPattern, searchPattern, searchPattern]);
        const list = result.rows.map(u => ({
            ...u,
            is_online: isUserOnline(u.id)
        }));
        res.json(list);
    } catch (err) {
        console.error('Erreur recherche:', err);
        res.status(500).json({ error: 'Erreur de recherche.' });
    }
});

app.get('/api/friends/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `
            SELECT 
                u.id, u.username, u.email, u.phone, u.profile_pic, u.status_message,
                (
                    SELECT m.content 
                    FROM messages m 
                    WHERE (m.sender_id = $1 AND m.receiver_id = u.id) OR (m.sender_id = u.id AND m.receiver_id = $2)
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_message,
                (
                    SELECT m.media_type 
                    FROM messages m 
                    WHERE (m.sender_id = $3 AND m.receiver_id = u.id) OR (m.sender_id = u.id AND m.receiver_id = $4)
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_media_type,
                (
                    SELECT m.sent_at 
                    FROM messages m 
                    WHERE (m.sender_id = $5 AND m.receiver_id = u.id) OR (m.sender_id = u.id AND m.receiver_id = $6)
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_message_time,
                (
                    SELECT COUNT(*) 
                    FROM messages m 
                    WHERE m.sender_id = u.id AND m.receiver_id = $7 AND (m.is_read = FALSE OR m.is_read IS NULL)
                ) AS unread_count
            FROM friendships f
            JOIN users u ON (u.id = CASE WHEN f.sender_id = $8 THEN f.receiver_id ELSE f.sender_id END)
            WHERE (f.sender_id = $9 OR f.receiver_id = $10) AND f.status = 'accepted'
            ORDER BY last_message_time DESC NULLS LAST, u.username ASC
        `;

        const result = await db.query(sql, [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId]);
        const friends = result.rows.map(f => ({
            ...f,
            is_online: isUserOnline(f.id)
        }));
        res.json(friends);
    } catch (err) {
        console.error('Erreur SQL friends:', err);
        res.status(500).json({ error: 'Erreur lors du chargement des amis.' });
    }
});

app.get('/api/friend-requests/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `
            SELECT f.id AS request_id, u.id AS sender_id, u.username, u.profile_pic, u.status_message
            FROM friendships f
            JOIN users u ON u.id = f.sender_id
            WHERE f.receiver_id = $1 AND f.status = 'pending'
        `;
        const result = await db.query(sql, [userId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Erreur requêtes amis.' });
    }
});

app.post('/api/friend-request', authenticateToken, async (req, res) => {
    const senderId = req.user.id || req.body.senderId;
    const receiverId = req.body.receiverId;
    if (!senderId || !receiverId || senderId == receiverId) {
        return res.status(400).json({ error: 'Paramètres invalides.' });
    }

    try {
        const checkSql = 'SELECT * FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $3 AND receiver_id = $4)';
        const checkRes = await db.query(checkSql, [senderId, receiverId, receiverId, senderId]);
        if (checkRes.rows.length > 0) {
            return res.status(400).json({ error: 'Une demande ou amitié existe déjà.' });
        }

        const insertSql = 'INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, \'pending\')';
        await db.query(insertSql, [senderId, receiverId]);
        io.to(`user_${receiverId}`).emit('friend_request_received', { senderId });
        res.json({ message: 'Demande envoyée !' });
    } catch (err) {
        res.status(500).json({ error: 'Erreur lors de l\'envoi.' });
    }
});

app.post('/api/friend-request/respond', authenticateToken, async (req, res) => {
    const { requestId, action } = req.body;
    if (!requestId || !action) return res.status(400).json({ error: 'Paramètres manquants.' });

    try {
        if (action === 'accept') {
            await db.query('UPDATE friendships SET status = \'accepted\' WHERE id = $1', [requestId]);
            const rRes = await db.query('SELECT sender_id, receiver_id FROM friendships WHERE id = $1', [requestId]);
            if (rRes.rows.length > 0) {
                io.to(`user_${rRes.rows[0].sender_id}`).emit('friend_request_accepted', { withUserId: rRes.rows[0].receiver_id });
                io.to(`user_${rRes.rows[0].receiver_id}`).emit('friend_request_accepted', { withUserId: rRes.rows[0].sender_id });
            }
            res.json({ message: 'Demande acceptée.' });
        } else {
            await db.query('DELETE FROM friendships WHERE id = $1', [requestId]);
            res.json({ message: 'Demande rejetée.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Erreur lors du traitement de la demande.' });
    }
});

// -------------------------------------------------------------
// ROUTES MESSAGES
// -------------------------------------------------------------

app.get('/api/messages/:user1/:user2', authenticateToken, async (req, res) => {
    const { user1, user2 } = req.params;
    try {
        const sql = `
            SELECT id, sender_id, receiver_id, group_id, content, media_type, sent_at, is_read
            FROM messages
            WHERE group_id IS NULL AND ((sender_id = $1 AND receiver_id = $2) OR (sender_id = $3 AND receiver_id = $4))
            ORDER BY sent_at ASC
        `;
        const result = await db.query(sql, [user1, user2, user2, user1]);
        res.json(result.rows);
    } catch (err) {
        console.error('Erreur messages:', err);
        res.status(500).json({ error: 'Erreur messages.' });
    }
});

app.post('/api/messages/read', authenticateToken, async (req, res) => {
    const { senderId, receiverId } = req.body;
    if (!senderId || !receiverId) return res.status(400).json({ error: 'Paramètres manquants' });

    try {
        const sql = 'UPDATE messages SET is_read = TRUE WHERE sender_id = $1 AND receiver_id = $2 AND (is_read = FALSE OR is_read IS NULL)';
        const result = await db.query(sql, [senderId, receiverId]);
        
        io.to(`user_${senderId}`).emit('messages_read_ack', {
            readBy: receiverId
        });

        res.json({ success: true, updated: result.rowCount });
    } catch (err) {
        res.status(500).json({ error: 'Erreur SQL' });
    }
});

// -------------------------------------------------------------
// ROUTES GROUPES
// -------------------------------------------------------------

app.post('/api/groups', authenticateToken, async (req, res) => {
    const created_by = req.user.id || req.body.created_by;
    const { name, group_pic, member_ids } = req.body;
    if (!name || !created_by) {
        return res.status(400).json({ error: 'Nom du groupe requis.' });
    }

    try {
        const groupSql = 'INSERT INTO "groups" (name, group_pic, created_by) VALUES ($1, $2, $3) RETURNING id';
        const groupResult = await db.query(groupSql, [name.trim(), group_pic || null, created_by]);
        const groupId = groupResult.rows[0].id;

        await db.query(`
            INSERT INTO group_members (group_id, user_id, role) 
            VALUES ($1, $2, 'admin') 
            ON CONFLICT (group_id, user_id) DO UPDATE SET role = 'admin'
        `, [groupId, created_by]);

        if (Array.isArray(member_ids) && member_ids.length > 0) {
            for (const uid of member_ids) {
                if (Number(uid) !== Number(created_by)) {
                    await db.query(`
                        INSERT INTO group_members (group_id, user_id, role) 
                        VALUES ($1, $2, 'member') 
                        ON CONFLICT (group_id, user_id) DO NOTHING
                    `, [groupId, uid]);
                    io.to(`user_${uid}`).emit('added_to_group', { groupId, name });
                }
            }
        }

        res.status(201).json({
            message: 'Groupe créé avec succès',
            groupId,
            group: { id: groupId, name, group_pic, created_by }
        });
    } catch (err) {
        console.error('Erreur création groupe:', err);
        res.status(500).json({ error: 'Erreur création groupe.' });
    }
});

app.get('/api/groups/user/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `
            SELECT 
                g.id, g.name, g.group_pic, g.created_by, g.created_at,
                gm.role AS my_role,
                (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS members_count,
                (
                    SELECT m.content 
                    FROM messages m 
                    WHERE m.group_id = g.id 
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_message,
                (
                    SELECT m.media_type 
                    FROM messages m 
                    WHERE m.group_id = g.id 
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_media_type,
                (
                    SELECT u.username 
                    FROM messages m 
                    JOIN users u ON u.id = m.sender_id 
                    WHERE m.group_id = g.id 
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_sender_name,
                (
                    SELECT m.sent_at 
                    FROM messages m 
                    WHERE m.group_id = g.id 
                    ORDER BY m.sent_at DESC LIMIT 1
                ) AS last_message_time
            FROM group_members gm
            JOIN "groups" g ON g.id = gm.group_id
            WHERE gm.user_id = $1
            ORDER BY last_message_time DESC NULLS LAST, g.name ASC
        `;
        const groups = await queryDB(sql, [userId]);
        res.json(groups);
    } catch (err) {
        console.error('Erreur serveur groupes:', err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/groups/:groupId/details', authenticateToken, async (req, res) => {
    const groupId = req.params.groupId;
    try {
        const groupRows = await queryDB('SELECT * FROM "groups" WHERE id = $1', [groupId]);
        if (groupRows.length === 0) return res.status(404).json({ error: 'Groupe non trouvé.' });

        const membersSql = `
            SELECT u.id, u.username, u.profile_pic, u.status_message, gm.role, gm.joined_at
            FROM group_members gm
            JOIN users u ON u.id = gm.user_id
            WHERE gm.group_id = $1
            ORDER BY gm.role ASC, u.username ASC
        `;
        const members = await queryDB(membersSql, [groupId]);

        const group = groupRows[0];
        const enrichedMembers = members.map(m => ({
            ...m,
            is_online: isUserOnline(m.id)
        }));

        res.json({
            ...group,
            members: enrichedMembers
        });
    } catch (err) {
        res.status(500).json({ error: 'Erreur détails groupe.' });
    }
});

app.get('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
    const groupId = req.params.groupId;
    try {
        const sql = `
            SELECT m.id, m.sender_id, m.group_id, m.content, m.media_type, m.sent_at,
                   u.username AS sender_username, u.profile_pic AS sender_profile_pic
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.group_id = $1
            ORDER BY m.sent_at ASC
        `;
        const messages = await queryDB(sql, [groupId]);
        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: 'Erreur messages groupe.' });
    }
});

app.put('/api/groups/:groupId/role', authenticateToken, async (req, res) => {
    const groupId = req.params.groupId;
    const requesterId = req.user.id || req.body.requesterId;
    const { targetUserId, newRole } = req.body;

    if (!targetUserId || !newRole || !requesterId) {
        return res.status(400).json({ error: 'Paramètres manquants.' });
    }

    try {
        const check = await queryDB('SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, requesterId]);
        if (check.length === 0 || check[0].role !== 'admin') {
            return res.status(403).json({ error: 'Seuls les administrateurs peuvent changer les rôles.' });
        }

        await db.query('UPDATE group_members SET role = $1 WHERE group_id = $2 AND user_id = $3', [newRole, groupId, targetUserId]);
        io.to(`group_${groupId}`).emit('group_members_updated', { groupId });
        res.json({ message: `Rôle mis à jour (${newRole}).` });
    } catch (err) {
        res.status(500).json({ error: 'Erreur rôle.' });
    }
});

app.delete('/api/groups/:groupId/members/:targetUserId', authenticateToken, async (req, res) => {
    const { groupId, targetUserId } = req.params;
    const requesterId = req.user.id || req.query.requesterId;

    try {
        if (Number(requesterId) !== Number(targetUserId)) {
            const check = await queryDB('SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, requesterId]);
            if (check.length === 0 || check[0].role !== 'admin') {
                return res.status(403).json({ error: 'Action non autorisée.' });
            }
        }

        await db.query('DELETE FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, targetUserId]);
        io.to(`group_${groupId}`).emit('group_members_updated', { groupId });
        io.to(`user_${targetUserId}`).emit('removed_from_group', { groupId });
        res.json({ message: 'Membre retiré du groupe.' });
    } catch (err) {
        res.status(500).json({ error: 'Erreur suppression membre.' });
    }
});

// -------------------------------------------------------------
// ROUTES STATUTS ÉPHÉMÈRES
// -------------------------------------------------------------

app.post('/api/statuses', authenticateToken, async (req, res) => {
    const user_id = req.user.id || req.body.user_id;
    const { content, media_url, media_type, bg_color, duration_hours } = req.body;
    if (!user_id || (!content && !media_url)) {
        return res.status(400).json({ error: 'Contenu ou média requis.' });
    }

    const duration = Number(duration_hours) > 0 ? Number(duration_hours) : 24;
    const mType = media_type || (media_url ? 'image' : 'text');
    const bg = bg_color || 'linear-gradient(135deg, #1a6eff, #0d3b8f)';

    try {
        const sql = `
            INSERT INTO statuses (user_id, content, media_url, media_type, bg_color, duration_hours, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + ($7 || ' hours')::interval)
            RETURNING id
        `;
        const result = await db.query(sql, [user_id, content || '', media_url || null, mType, bg, duration, duration]);

        io.emit('new_status_alert', { user_id });

        res.status(201).json({
            message: 'Statut publié avec succès',
            statusId: result.rows[0].id
        });
    } catch (err) {
        console.error('Erreur publication statut:', err);
        res.status(500).json({ error: 'Erreur publication statut.' });
    }
});

app.get('/api/statuses/feed/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `
            SELECT 
                s.id, s.user_id, s.content, s.media_url, s.media_type, s.bg_color, s.duration_hours, s.created_at, s.expires_at,
                u.username, u.profile_pic,
                (SELECT COUNT(*) FROM status_views sv WHERE sv.status_id = s.id) AS views_count,
                (SELECT COUNT(*) FROM status_views sv WHERE sv.status_id = s.id AND sv.viewer_id = $1) > 0 AS has_viewed
            FROM statuses s
            JOIN users u ON u.id = s.user_id
            WHERE s.expires_at > NOW() AND (
                s.user_id = $2 OR s.user_id IN (
                    SELECT CASE WHEN f.sender_id = $3 THEN f.receiver_id ELSE f.sender_id END
                    FROM friendships f
                    WHERE (f.sender_id = $4 OR f.receiver_id = $5) AND f.status = 'accepted'
                )
            )
            ORDER BY s.created_at DESC
        `;
        const rows = await queryDB(sql, [userId, userId, userId, userId, userId]);

        const userMap = new Map();
        rows.forEach(item => {
            const uid = item.user_id;
            if (!userMap.has(uid)) {
                userMap.set(uid, {
                    user_id: uid,
                    username: item.username,
                    profile_pic: item.profile_pic,
                    is_me: Number(uid) === Number(userId),
                    all_viewed: true,
                    statuses: []
                });
            }

            const uData = userMap.get(uid);
            if (!item.has_viewed && !uData.is_me) {
                uData.all_viewed = false;
            }
            uData.statuses.push(item);
        });

        res.json(Array.from(userMap.values()));
    } catch (err) {
        console.error('Erreur flux statuts:', err);
        res.status(500).json({ error: 'Erreur flux statuts.' });
    }
});

app.post('/api/statuses/:statusId/view', authenticateToken, async (req, res) => {
    const statusId = req.params.statusId;
    const viewerId = req.user.id || req.body.viewerId;
    if (!viewerId) return res.status(400).json({ error: 'viewerId requis' });

    try {
        await db.query(`
            INSERT INTO status_views (status_id, viewer_id, viewed_at) 
            VALUES ($1, $2, NOW()) 
            ON CONFLICT (status_id, viewer_id) DO NOTHING
        `, [statusId, viewerId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Erreur vue statut.' });
    }
});

app.get('/api/statuses/:statusId/views', authenticateToken, async (req, res) => {
    const statusId = req.params.statusId;
    try {
        const sql = `
            SELECT sv.viewed_at, u.id, u.username, u.profile_pic
            FROM status_views sv
            JOIN users u ON u.id = sv.viewer_id
            WHERE sv.status_id = $1
            ORDER BY sv.viewed_at DESC
        `;
        const viewers = await queryDB(sql, [statusId]);
        res.json(viewers);
    } catch (err) {
        res.status(500).json({ error: 'Erreur vues.' });
    }
});

app.delete('/api/statuses/:statusId', authenticateToken, async (req, res) => {
    const statusId = req.params.statusId;
    const userId = req.user.id || req.body.userId;

    try {
        const result = await db.query('DELETE FROM statuses WHERE id = $1 AND user_id = $2', [statusId, userId]);
        if (result.rowCount > 0) {
            io.emit('status_deleted', { statusId });
            res.json({ message: 'Statut supprimé avec succès.' });
        } else {
            res.status(403).json({ error: 'Action non autorisée.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Erreur suppression.' });
    }
});

// -------------------------------------------------------------
// WEBSOCKETS AUTHENTIFIÉS
// -------------------------------------------------------------

io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if (!token) return next();

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (!err && decoded) {
            socket.userId = Number(decoded.id);
            socket.user = decoded;
        }
        next();
    });
});

io.on('connection', (socket) => {
    let currentUserId = socket.userId || null;

    socket.on('join', (userId) => {
        const validUserId = socket.userId || Number(userId);
        if (!validUserId) return;

        currentUserId = validUserId;
        socket.join(`user_${currentUserId}`);

        if (!onlineUsers.has(currentUserId)) {
            onlineUsers.set(currentUserId, new Set());
        }
        onlineUsers.get(currentUserId).add(socket.id);

        io.emit('user_status', {
            userId: currentUserId,
            is_online: true
        });
    });

    socket.on('join_group', (groupId) => {
        if (groupId) socket.join(`group_${groupId}`);
    });

    socket.on('leave_group', (groupId) => {
        if (groupId) socket.leave(`group_${groupId}`);
    });

    // Envoi de message direct
    socket.on('send_message', async (data) => {
        const verifiedSenderId = socket.userId || Number(data.sender_id);
        const { receiver_id, content, media_type } = data;
        if (!verifiedSenderId || !receiver_id || (!content && !media_type)) return;

        const mType = media_type || 'text';
        const textContent = content || '';

        try {
            const sql = `
                INSERT INTO messages (sender_id, receiver_id, content, media_type, sent_at, is_read) 
                VALUES ($1, $2, $3, $4, NOW(), FALSE) 
                RETURNING *
            `;
            const result = await db.query(sql, [verifiedSenderId, receiver_id, textContent, mType]);
            const savedMessage = result.rows[0];

            io.to(`user_${receiver_id}`).emit('receive_message', savedMessage);
            io.to(`user_${verifiedSenderId}`).emit('message_sent_confirm', savedMessage);
        } catch (err) {
            console.error('Erreur enregistrement message:', err);
        }
    });

    // Envoi de message dans un groupe
    socket.on('send_group_message', async (data) => {
        const verifiedSenderId = socket.userId || Number(data.sender_id);
        const { group_id, content, media_type } = data;
        if (!verifiedSenderId || !group_id || (!content && !media_type)) return;

        try {
            const mType = media_type || 'text';
            const textContent = content || '';

            const sql = `
                INSERT INTO messages (sender_id, group_id, content, media_type, sent_at, is_read) 
                VALUES ($1, $2, $3, $4, NOW(), FALSE) 
                RETURNING id
            `;
            const res = await db.query(sql, [verifiedSenderId, group_id, textContent, mType]);

            const fetchSql = `
                SELECT m.id, m.sender_id, m.group_id, m.content, m.media_type, m.sent_at,
                       u.username AS sender_username, u.profile_pic AS sender_profile_pic
                FROM messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.id = $1
            `;
            const rows = await queryDB(fetchSql, [res.rows[0].id]);
            if (rows.length > 0) {
                io.to(`group_${group_id}`).emit('receive_group_message', rows[0]);
            }
        } catch (err) {
            console.error('Erreur message groupe:', err);
        }
    });

    socket.on('typing', (data) => {
        const verifiedSenderId = socket.userId || Number(data.sender_id);
        if (data.receiver_id) {
            io.to(`user_${data.receiver_id}`).emit('typing_indicator', {
                sender_id: verifiedSenderId,
                isTyping: true
            });
        }
    });

    socket.on('stop_typing', (data) => {
        const verifiedSenderId = socket.userId || Number(data.sender_id);
        if (data.receiver_id) {
            io.to(`user_${data.receiver_id}`).emit('typing_indicator', {
                sender_id: verifiedSenderId,
                isTyping: false
            });
        }
    });

    socket.on('group_typing', (data) => {
        const verifiedSenderId = socket.userId || Number(data.sender_id);
        if (data.group_id) {
            socket.to(`group_${data.group_id}`).emit('group_typing_indicator', {
                sender_id: verifiedSenderId,
                sender_name: data.sender_name,
                group_id: data.group_id,
                isTyping: true
            });
        }
    });

    socket.on('group_stop_typing', (data) => {
        const verifiedSenderId = socket.userId || Number(data.sender_id);
        if (data.group_id) {
            socket.to(`group_${data.group_id}`).emit('group_typing_indicator', {
                sender_id: verifiedSenderId,
                group_id: data.group_id,
                isTyping: false
            });
        }
    });

    socket.on('disconnect', () => {
        if (currentUserId && onlineUsers.has(currentUserId)) {
            const userSockets = onlineUsers.get(currentUserId);
            userSockets.delete(socket.id);
            if (userSockets.size === 0) {
                onlineUsers.delete(currentUserId);
                io.emit('user_status', {
                    userId: currentUserId,
                    is_online: false
                });
            }
        }
    });
});

// Port d'écoute et initialisation
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
    console.log(`🚀 Serveur Dark Link (PostgreSQL) démarré sur le port ${PORT}`);
    await initDatabase();
});
