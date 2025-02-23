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
        await pool.query(`
            INSERT INTO users (nickname, password, avatar)
            VALUES ($1, $2, $3)
            ON CONFLICT (nickname) DO NOTHING`, 
            [nickname, hashedPassword, defaultAvatar]);
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
        return await bcrypt.compare(password, user.password);
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
            ORDER BY id ASC 
            LIMIT ${MAX_MESSAGES}`, [room]);
        return res.rows.map(row => ({
            username: row.username,
            msg: row.msg,
            timestamp: row.timestamp,
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
        const res = await pool.query('SELECT * FROM users WHERE nickname = $1', [username]);
        if (res.rows.length > 0) {
            return {
                deleteMessages: res.rows[0].delete_messages || false,
                muteUsers: res.rows[0].mute_users || false,
                banUsers: res.rows[0].ban_users || false,
                clearChat: res.rows[0].clear_chat || false,
                assignGroups: res.rows[0].assign_groups || false
            };
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
            const groupsRes = await pool.query('SELECT group_name FROM user_groups WHERE nickname = $1', [username]);
            return {
                nickname: user.nickname,
                avatar: user.avatar,
                age: user.age,
                last_seen: user.last_seen,
                bio: user.bio,
                achievements: user.achievements || [],
                groups: groupsRes.rows.map(row => row.group_name)
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

async function assignGroup(targetUsername, groupName) {
    try {
        await pool.query(`
            INSERT INTO user_groups (nickname, group_name)
            VALUES ($1, $2)
            ON CONFLICT (nickname, group_name) DO NOTHING`, 
            [targetUsername, groupName]);
        if (groupName.toLowerCase() === "администратор") {
            await pool.query(`
                UPDATE users
                SET delete_messages = true,
                    mute_users = true,
                    ban_users = true,
                    clear_chat = true,
                    assign_groups = true
                WHERE nickname = $1`, [targetUsername]);
        } else if (groupName.toLowerCase() === "модератор") {
            await pool.query(`
                UPDATE users
                SET delete_messages = true,
                    mute_users = true,
                    ban_users = false,
                    clear_chat = false,
                    assign_groups = false
                WHERE nickname = $1`, [targetUsername]);
        }
    } catch (err) {
        console.error("Ошибка назначения группы:", err.message);
    }
}

io.on("connection", (socket) => {
    socket.on("auth", async ({ nickname, password }) => {
        const isValid = await verifyUser(nickname, password);
        if (isValid) {
            const token = jwt.sign({ nickname }, JWT_SECRET, { expiresIn: '1h' });
            users.set(socket.id, nickname);
            const permissions = await getUserPermissions(nickname); // Исправлено: передаём nickname
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
            users.set(socket.id, nickname);
            const permissions = await getUserPermissions(nickname); // Исправлено: передаём nickname
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
        const timestamp = new Date().toLocaleTimeString();
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
        }
    });

    socket.on("update profile", async ({ avatar, age, bio }) => {
        const username = users.get(socket.id);
        if (!username) return;
        await updateUserProfile(username, { avatar, age, bio });
        socket.emit("profile updated", "Профиль обновлён");
    });

    socket.on("assign group", async ({ targetUsername, groupName }) => {
        const username = users.get(socket.id);
        if (!username) return;
        const permissions = await getUserPermissions(username);
        if (permissions.assignGroups) {
            await assignGroup(targetUsername, groupName);
            io.emit("group assigned", `${targetUsername} теперь ${groupName}`);
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