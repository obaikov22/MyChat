const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http, { cors: { origin: "*" } });
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const currentRoom = new Map(); // Хранит канал для каждого socket.id

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const MAX_MESSAGES = 100;

const pool = new Pool({
    connectionString: "postgresql://chat_user:ta0SjNKfaOEUiWgoKPXAWMp58PfuxUFb@dpg-cusu4qdumphs73ccucu0-a.oregon-postgres.render.com/chat_9oa7",
    ssl: { rejectUnauthorized: false }
});

const users = new Map();
const channelUsers = new Map(); // Хранит пользователей по каналам: channel -> Set(nicknames)
const mutedUsers = new Map();

pool.connect()
    .then(() => console.log("Подключено к PostgreSQL"))
    .catch(err => console.error("Ошибка подключения к PostgreSQL:", err.message));

app.use(express.static(__dirname));

app.use(cookieParser());
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

async function saveUser(nickname, password) {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const defaultAvatar = "/default-avatar.png"; // Используем локальный файл
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

async function saveMessage({ channel, username, msg, timestamp, messageId, replyTo, type, media }) {
    try {
        await pool.query(`
            INSERT INTO messages (channel, username, msg, timestamp, message_id, reply_to, type, media)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [channel, username, msg, timestamp, messageId, replyTo, type, media]);
    } catch (err) {
        console.error("Ошибка сохранения сообщения:", err.message);
    }
}

async function getChatHistory(channel) {
    try {
        const res = await pool.query(`
            SELECT m.*, u.avatar 
            FROM messages m
            JOIN users u ON m.username = u.nickname
            WHERE m.room = $1 
            ORDER BY m.id ASC 
            LIMIT ${MAX_MESSAGES}`, [channel]);
        return res.rows.map(row => ({
            username: row.username,
            msg: row.msg,
            timestamp: row.timestamp,
            messageId: row.message_id,
            replyTo: row.reply_to,
            type: row.type,
            media: row.media,
            avatar: row.avatar || "/default-avatar.png"
        }));
    } catch (err) {
        console.error("Ошибка загрузки истории:", err.message);
        return [];
    }
}

async function getUserAvatar(nickname) {
    const result = await pool.query('SELECT avatar FROM users WHERE nickname = $1', [nickname]);
    return result.rows[0]?.avatar || "/default-avatar.png";
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
        const res = await pool.query('SELECT nickname, avatar FROM users');
        return res.rows.map(row => ({
            nickname: row.nickname,
            avatar: row.avatar || "/default-avatar.png"
        }));
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
                avatar: user.avatar || "/default-avatar.png",
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
        const allUsers = await getAllUsers();
        io.emit("update users avatars", allUsers);
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
    socket.on("auth", async ({ nickname, password, rememberMe }) => {
        const existingSocketId = [...users.entries()].find(([_, name]) => name === nickname)?.[0];
        if (existingSocketId && existingSocketId !== socket.id) {
            users.delete(existingSocketId);
            io.sockets.sockets.get(existingSocketId)?.disconnect();
        }
        const isValid = await verifyUser(nickname, password);
        if (isValid) {
            const token = jwt.sign({ nickname }, JWT_SECRET, { expiresIn: rememberMe ? '30d' : '1h' });
            users.set(socket.id, nickname);
            const permissions = await getUserPermissions(nickname);
            // Сохраняем токен в cookies
            socket.handshake.headers.cookie = `chatToken=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${rememberMe ? 2592000 : 3600}`; // 30 дней или 1 час
            socket.emit("auth success", { nickname, token, permissions });
            const allUsers = await getAllUsers();
            const onlineUsers = Array.from(users.values());
            io.emit("update users", { 
                users: allUsers, 
                onlineUsers,
                onlineCount: onlineUsers.length, 
                totalCount: allUsers.length 
            });
        } else {
            socket.emit("auth error", "Неверный ник или пароль");
        }
    });

    socket.on("auto login", async (token) => {
        // Если токен не передан, попробуем взять его из cookies
        if (!token && socket.request.headers.cookie) {
            const cookies = cookieParser.parse(socket.request.headers.cookie);
            token = cookies.chatToken;
        }
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const nickname = decoded.nickname;
            const existingSocketId = [...users.entries()].find(([_, name]) => name === nickname)?.[0];
            if (existingSocketId && existingSocketId !== socket.id) {
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
                onlineUsers,
                onlineCount: onlineUsers.length, 
                totalCount: allUsers.length 
            });
        } catch (err) {
            socket.emit("auth error", "Неверный или просроченный токен");
        }
    });

    socket.on("chat message", async ({ channel, msg, replyTo, media }) => {
        const nickname = users.get(socket.id);
        if (!nickname || isMuted(nickname, channel)) return;
        const messageId = generateMessageId();
        const timestamp = new Date().toISOString();
        const avatar = await getUserAvatar(nickname);
        await pool.query(
            'INSERT INTO messages (channel, username, msg, timestamp, message_id, reply_to, type, media) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [channel, nickname, msg, timestamp, messageId, replyTo, media ? 'media' : 'message', media]
        );
        io.to(channel).emit("chat message", { username: nickname, msg, timestamp, messageId, replyTo, media, type: media ? 'media' : 'message', avatar });
    });

    socket.on("join room", async (channel) => {
        const nickname = users.get(socket.id);
        if (!nickname) return socket.emit("auth error", "Не авторизован");
    
        // Покидаем текущий канал (если есть)
        const currentChannel = currentRoom.get(socket.id) || "room1";
        if (currentChannel && channelUsers.has(currentChannel)) {
            channelUsers.get(currentChannel).delete(nickname);
        }
    
        // Присоединяемся к новому каналу
        socket.join(channel);
        currentRoom.set(socket.id, channel);
    
        // Обновляем список пользователей в новом канале
        if (!channelUsers.has(channel)) {
            channelUsers.set(channel, new Set());
        }
        channelUsers.get(channel).add(nickname);
    
        // Загружаем историю сообщений для канала
        loadChatHistory(socket, channel);
    
        // Обновляем пользователей для всех в канале
        io.to(channel).emit("update users", {
            users: await getAllUsers(),
            onlineUsers: Array.from(channelUsers.get(channel)),
            onlineCount: channelUsers.get(channel).size,
            totalCount: (await getAllUsers()).length,
            channel: channel
        });
    });

    async function loadChatHistory(socket, channel) {
        const result = await pool.query('SELECT * FROM messages WHERE channel = $1 ORDER BY timestamp ASC LIMIT $2', [channel, MAX_MESSAGES]);
        socket.emit("chat history", result.rows);
    }

    socket.on("delete message", async ({ channel, messageId }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.deleteMessages) {
            await pool.query('DELETE FROM messages WHERE message_id = $1 AND channel = $2', [messageId, channel]);
            io.to(channel).emit("message deleted", messageId);
        }
    });

    socket.on("clear chat", async (channel) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.clearChat) {
            await pool.query('DELETE FROM messages WHERE room = $1', [channel]);
            io.to(channel).emit("chat cleared");
        }
    });

    socket.on("mute user", async ({ channel, targetUsername, duration }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.muteUsers) {
            const targetSocketId = [...users.entries()].find(([_, name]) => name === targetUsername)?.[0];
            if (targetSocketId) {
                mutedUsers.set(targetSocketId, Date.now() + duration * 1000);
                io.to(channel).emit("user muted", { username: targetUsername, duration });
            }
        }
    });

    socket.on("ban user", async ({ channel, targetUsername }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.banUsers) {
            const targetSocketId = [...users.entries()].find(([_, name]) => name === targetUsername)?.[0];
            if (targetSocketId) {
                users.delete(targetSocketId);
                await pool.query('DELETE FROM users WHERE nickname = $1', [targetUsername]);
                io.to(channel).emit("user banned", targetUsername);
                const allUsers = await getAllUsers();
                const onlineUsers = Array.from(users.values());
                io.emit("update users", { 
                    users: allUsers, 
                    onlineUsers,
                    onlineCount: onlineUsers.length, 
                    totalCount: allUsers.length 
                });
                io.sockets.sockets.get(targetSocketId)?.disconnect();
            }
        }
    });

    socket.on("typing", (channel) => {
        const username = users.get(socket.id);
        if (username) socket.to(channel).emit("typing", username);
    });

    socket.on("stop typing", (channel) => {
        socket.to(channel).emit("stop typing");
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
        const nickname = users.get(socket.id);
        if (nickname) {
            users.delete(socket.id);
            await pool.query('UPDATE users SET last_seen = NOW() WHERE nickname = $1', [nickname]);
            const allUsers = await getAllUsers();
            const onlineUsers = Array.from(users.values());
            io.emit("update users", { 
                users: allUsers, 
                onlineUsers,
                onlineCount: onlineUsers.length, 
                totalCount: allUsers.length 
            });
        }
        // Очищаем cookies при отключении
        if (socket.request.headers.cookie) {
            socket.handshake.headers.cookie = `chatToken=; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
        }
    });
});

http.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});