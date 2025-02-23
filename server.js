const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http, { cors: { origin: "*" } });
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const MAX_MESSAGES = 100;

const pool = new Pool({
    connectionString: "postgresql://chat_user:ta0SjNKfaOEUiWgoKPXAWMp58PfuxUFb@dpg-cusu4qdumphs73ccucu0-a/chat_9oa7",
    ssl: { rejectUnauthorized: false }
});

const users = new Map();
const mutedUsers = new Map();

pool.connect()
    .then(() => console.log("Подключено к PostgreSQL"))
    .catch(err => console.error("Ошибка подключения к PostgreSQL:", err.message));

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

async function saveUser(nickname, password) {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const defaultAvatar = "default-avatar.png";
        const role = nickname.toLowerCase() === "admin" ? 'admin' : 'user';
        await pool.query(`
            INSERT INTO users (nickname, password, avatar, role)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (nickname) DO UPDATE 
            SET password = EXCLUDED.password, 
                avatar = COALESCE(EXCLUDED.avatar, users.avatar), 
                role = EXCLUDED.role`,
            [nickname, hashedPassword, defaultAvatar, role]);
    } catch (err) {
        console.error("Ошибка сохранения пользователя:", err.message);
    }
}

async function verifyUser(nickname, password) {
    try {
        const res = await pool.query('SELECT * FROM users WHERE nickname = $1', [nickname]);
        if (res.rows.length === 0) {
            await saveUser(nickname, password);
            return true;
        }
        const user = res.rows[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (isValid && nickname.toLowerCase() === "admin" && user.role !== 'admin') {
            await pool.query(`
                UPDATE users 
                SET role = 'admin'
                WHERE nickname = $1`, [nickname]);
        }
        return isValid;
    } catch (err) {
        console.error("Ошибка проверки пользователя:", err.message);
        return false;
    }
}

async function saveMessage({ room, username, msg, timestamp, messageId, replyTo, type, media }) {
    try {
        await pool.query(`
            INSERT INTO messages (room, username, msg, timestamp, message_id, reply_to, type, media)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [room, username, msg, timestamp, messageId, replyTo, type, media]);
    } catch (err) {
        console.error("Ошибка сохранения сообщения:", err.message);
    }
}

async function getChatHistory(room) {
    try {
        const res = await pool.query(`
            SELECT * FROM messages 
            WHERE room = $1 
            ORDER BY timestamp ASC 
            LIMIT ${MAX_MESSAGES}`, [room]);
        return res.rows.map(row => ({
            username: row.username,
            msg: row.msg,
            timestamp: new Date(row.timestamp).toLocaleTimeString(), // Форматируем время
            messageId: row.message_id,
            replyTo: row.reply_to,
            type: row.type,
            media: row.media
        }));
    } catch (err) {
        console.error("Ошибка загрузки истории:", err.message);
        return [];
    }
}

async function getUserPermissions(username) {
    try {
        const res = await pool.query('SELECT role FROM users WHERE nickname = $1', [username]);
        if (res.rows.length > 0) {
            const role = res.rows[0].role || 'user';
            if (role === 'admin') {
                return {
                    deleteMessages: true,
                    muteUsers: true,
                    banUsers: true,
                    clearChat: true,
                    assignGroups: true
                };
            } else if (role === 'moderator') {
                return {
                    deleteMessages: true,
                    muteUsers: true,
                    banUsers: false,
                    clearChat: false,
                    assignGroups: false
                };
            }
        }
        return { deleteMessages: false, muteUsers: false, banUsers: false, clearChat: false, assignGroups: false };
    } catch (err) {
        console.error("Ошибка получения прав:", err.message);
        return { deleteMessages: false, muteUsers: false, banUsers: false, clearChat: false, assignGroups: false };
    }
}

async function getAllUsers() {
    try {
        const res = await pool.query('SELECT nickname FROM users');
        return res.rows.map(row => row.nickname);
    } catch (err) {
        console.error("Ошибка получения списка пользователей:", err.message);
        return [];
    }
}

async function getUserProfile(username) {
    try {
        const res = await pool.query('SELECT * FROM users WHERE nickname = $1', [username]);
        if (res.rows.length > 0) {
            const user = res.rows[0];
            return {
                nickname: user.nickname,
                avatar: user.avatar,
                age: user.age,
                last_seen: user.last_seen,
                bio: user.bio,
                achievements: user.achievements || [],
                role: user.role || 'user'
            };
        }
        return null;
    } catch (err) {
        console.error("Ошибка получения профиля:", err.message);
        return null;
    }
}

async function updateUserProfile(username, { avatar, age, bio }) {
    try {
        await pool.query(`
            UPDATE users 
            SET avatar = COALESCE($1, avatar), 
                age = COALESCE($2, age), 
                bio = COALESCE($3, bio), 
                last_seen = NOW()
            WHERE nickname = $4`, 
            [avatar, age, bio, username]);
    } catch (err) {
        console.error("Ошибка обновления профиля:", err.message);
    }
}

async function assignRole(targetUsername, role) {
    try {
        await pool.query(`
            UPDATE users 
            SET role = $1
            WHERE nickname = $2`, 
            [role, targetUsername]);
    } catch (err) {
        console.error("Ошибка назначения роли:", err.message);
    }
}

io.on("connection", (socket) => {
    socket.on("auth", async ({ nickname, password }) => {
        const existingSocketId = [...users.entries()].find(([_, name]) => name === nickname)?.[0];
        if (existingSocketId) {
            users.delete(existingSocketId);
            io.sockets.sockets.get(existingSocketId)?.disconnect();
        }
        const isValid = await verifyUser(nickname, password);
        if (isValid) {
            const token = jwt.sign({ nickname }, JWT_SECRET, { expiresIn: '1h' });
            users.set(socket.id, nickname);
            const permissions = await getUserPermissions(nickname);
            socket.emit("auth success", { nickname, token, permissions });
            const allUsers = await getAllUsers();
            const onlineUsers = Array.from(users.values());
            io.emit("update users", { 
                users: allUsers, 
                onlineCount: onlineUsers.length, 
                totalCount: allUsers.length 
            });
        } else {
            socket.emit("auth error", "Неверный ник или пароль");
        }
    });

    socket.on("auto login", async (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const nickname = decoded.nickname;
            const existingSocketId = [...users.entries()].find(([_, name]) => name === nickname)?.[0];
            if (existingSocketId) {
                users.delete(existingSocketId);
                io.sockets.sockets.get(existingSocketId)?.disconnect();
            }
            users.set(socket.id, nickname);
            const permissions = await getUserPermissions(nickname);
            socket.emit("auth success", { nickname, token, permissions });
            const allUsers = await getAllUsers();
            const onlineUsers = Array.from(users.values());
            io.emit("update users", { 
                users: allUsers, 
                onlineCount: onlineUsers.length, 
                totalCount: allUsers.length 
            });
        } catch (err) {
            socket.emit("auth error", "Неверный или просроченный токен");
        }
    });

    socket.on("chat message", async ({ room, msg, replyTo, media }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const isMuted = mutedUsers.has(socket.id) && mutedUsers.get(socket.id) > Date.now();
        if (isMuted) {
            socket.emit("muted", "Вы не можете отправлять сообщения, так как находитесь в муте");
            return;
        }
        const timestamp = new Date().toLocaleTimeString(); // Используем локальное время
        const messageId = Date.now() + "-" + Math.random().toString(36).substr(2, 9);
        const permissions = await getUserPermissions(username);
        const messageData = { 
            room, 
            username, 
            msg: msg || "", 
            timestamp, 
            messageId, 
            replyTo, 
            type: "message",
            media
        };
        if (permissions.assignGroups && msg.startsWith("/add ")) {
            const announcement = msg.slice(5).trim();
            if (announcement) {
                messageData.msg = announcement;
                messageData.type = "announcement";
                messageData.media = null;
                io.to(room).emit("announcement", messageData);
                await saveMessage(messageData);
            }
            return;
        }
        io.to(room).emit("chat message", messageData);
        await saveMessage(messageData);
    });

    socket.on("join room", async (room) => {
        socket.join(room);
        const history = await getChatHistory(room);
        socket.emit("chat history", history);
    });

    socket.on("delete message", async ({ room, messageId }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.deleteMessages) {
            await pool.query('DELETE FROM messages WHERE message_id = $1 AND room = $2', [messageId, room]);
            io.to(room).emit("message deleted", messageId);
        }
    });

    socket.on("clear chat", async (room) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.clearChat) {
            await pool.query('DELETE FROM messages WHERE room = $1', [room]);
            io.to(room).emit("chat cleared");
        }
    });

    socket.on("mute user", async ({ room, targetUsername, duration }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.muteUsers) {
            const targetSocketId = [...users.entries()].find(([_, name]) => name === targetUsername)?.[0];
            if (targetSocketId) {
                mutedUsers.set(targetSocketId, Date.now() + duration * 1000);
                io.to(room).emit("user muted", { username: targetUsername, duration });
            }
        }
    });

    socket.on("ban user", async ({ room, targetUsername }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.banUsers) {
            const targetSocketId = [...users.entries()].find(([_, name]) => name === targetUsername)?.[0];
            if (targetSocketId) {
                users.delete(targetSocketId);
                await pool.query('DELETE FROM users WHERE nickname = $1', [targetUsername]);
                io.to(room).emit("user banned", targetUsername);
                const allUsers = await getAllUsers();
                const onlineUsers = Array.from(users.values());
                io.emit("update users", { 
                    users: allUsers, 
                    onlineCount: onlineUsers.length, 
                    totalCount: allUsers.length 
                });
                io.sockets.sockets.get(targetSocketId)?.disconnect();
            }
        }
    });

    socket.on("typing", (room) => {
        const username = users.get(socket.id);
        if (username) socket.to(room).emit("typing", username);
    });

    socket.on("stop typing", (room) => {
        socket.to(room).emit("stop typing");
    });

    socket.on("get profile", async (targetUsername) => {
        const username = users.get(socket.id);
        if (!username) return;
        const profile = await getUserProfile(targetUsername);
        if (profile) {
            const permissions = await getUserPermissions(username);
            socket.emit("profile data", { 
                ...profile, 
                isOwnProfile: username === targetUsername, 
                canAssignGroups: permissions.assignGroups 
            });
        } else {
            socket.emit("profile data", null);
        }
    });

    socket.on("update profile", async ({ avatar, age, bio }) => {
        const username = users.get(socket.id);
        if (!username) return;
        await updateUserProfile(username, { avatar, age, bio });
        socket.emit("profile updated", "Профиль обновлён");
    });

    socket.on("assign group", async ({ targetUsername, role }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.assignGroups) {
            await assignRole(targetUsername, role.toLowerCase());
            io.emit("group assigned", `${targetUsername} теперь ${role === 'admin' ? 'Администратор' : 'Модератор'}`);
        }
    });

    socket.on("disconnect", async () => {
        const username = users.get(socket.id);
        if (username) {
            users.delete(socket.id);
            await pool.query('UPDATE users SET last_seen = NOW() WHERE nickname = $1', [username]);
            const allUsers = await getAllUsers();
            const onlineUsers = Array.from(users.values());
            io.emit("update users", { 
                users: allUsers, 
                onlineCount: onlineUsers.length, 
                totalCount: allUsers.length 
            });
        }
    });
});

http.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});