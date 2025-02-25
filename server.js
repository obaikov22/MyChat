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
const currentRoom = new Map(); // Хранит комнату для каждого socket.id
const channelUsers = new Map(); // Хранит пользователей по комнатам: room -> Set(nicknames)
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

async function saveMessage({ room, nickname, msg, timestamp, messageId, replyTo, type, media }) {
    try {
        await pool.query(`
            INSERT INTO messages (room, nickname, msg, timestamp, message_id, reply_to, type, media)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [room, nickname, msg, timestamp, messageId, replyTo, type, media]);
    } catch (err) {
        console.error("Ошибка сохранения сообщения:", err.message);
    }
}

async function loadChatHistory(socket, room) {
    const result = await pool.query('SELECT m.*, u.nickname FROM messages m LEFT JOIN users u ON m.username = u.nickname WHERE m.room = $1 ORDER BY m.timestamp ASC LIMIT $2', [room, MAX_MESSAGES]);
    socket.emit("chat history", result.rows.map(row => ({
        username: row.nickname, // Используем nickname вместо username
        msg: row.msg,
        timestamp: row.timestamp,
        messageId: row.message_id,
        replyTo: row.reply_to,
        type: row.type,
        media: row.media,
        avatar: row.avatar || "/default-avatar.png"
    })));
}

async function getUserPermissions(nickname) {
    try {
        const res = await pool.query('SELECT role FROM users WHERE nickname = $1', [nickname]);
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

async function getUserProfile(nickname) {
    try {
        const res = await pool.query('SELECT * FROM users WHERE nickname = $1', [nickname]);
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

async function getUserAvatar(nickname) {
    const result = await pool.query('SELECT avatar FROM users WHERE nickname = $1', [nickname]);
    return result.rows[0]?.avatar || "/default-avatar.png";
}

async function updateUserProfile(nickname, { avatar, age, bio }) {
    try {
        await pool.query(`
            UPDATE users 
            SET avatar = COALESCE($1, avatar), 
                age = COALESCE($2, age), 
                bio = COALESCE($3, bio), 
                last_seen = NOW()
            WHERE nickname = $4`, 
            [avatar, age, bio, nickname]);
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
    socket.on("auth", async ({ nickname, password }) => {
        const existingSocketId = [...users.entries()].find(([_, name]) => name === nickname)?.[0];
        if (existingSocketId && existingSocketId !== socket.id) {
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
                users: await getAllUsers, 
                onlineUsers,
                onlineCount: onlineUsers.length, 
                totalCount: (await getAllUsers()).length 
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
                users: await getAllUsers, 
                onlineUsers,
                onlineCount: onlineUsers.length, 
                totalCount: (await getAllUsers()).length 
            });
        } catch (err) {
            socket.emit("auth error", "Неверный или просроченный токен");
        }
    });

    socket.on("chat message", async ({ room, msg, replyTo, media }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const isMuted = mutedUsers.has(socket.id) && mutedUsers.get(socket.id) > Date.now();
        if (isMuted) {
            socket.emit("muted", "Вы не можете отправлять сообщения, так как находитесь в муте");
            return;
        }
        const timestamp = new Date().toLocaleTimeString();
        const messageId = Date.now() + "-" + Math.random().toString(36).substr(2, 9);
        const permissions = await getUserPermissions(nickname);
        const userProfile = await getUserProfile(nickname);
        const messageData = { 
            room, 
            nickname, 
            msg: msg || "", 
            timestamp, 
            messageId, 
            replyTo, 
            type: "message",
            media,
            avatar: userProfile.avatar
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
        const nickname = users.get(socket.id);
        if (!nickname) return socket.emit("auth error", "Не авторизован");
    
        // Покидаем текущую комнату (если есть)
        const currentRoomValue = currentRoom.get(socket.id) || "room1";
        if (currentRoomValue && channelUsers.has(currentRoomValue)) {
            channelUsers.get(currentRoomValue).delete(nickname);
        }
    
        // Присоединяемся к новой комнате
        socket.join(room);
        currentRoom.set(socket.id, room);
    
        // Обновляем список пользователей в новой комнате
        if (!channelUsers.has(room)) {
            channelUsers.set(room, new Set());
        }
        channelUsers.get(room).add(nickname);
    
        // Загружаем историю сообщений для комнаты
        loadChatHistory(socket, room);
    
        // Обновляем пользователей для всех в комнате
        io.to(room).emit("update users", {
            users: await getAllUsers(), // Убедимся, что это массив
            onlineUsers: Array.from(channelUsers.get(room)),
            onlineCount: channelUsers.get(room).size,
            totalCount: (await getAllUsers()).length,
            room: room
        });
    });

    socket.on("delete message", async ({ room, messageId }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const permissions = await getUserPermissions(nickname);
        if (permissions.deleteMessages) {
            await pool.query('DELETE FROM messages WHERE message_id = $1 AND room = $2', [messageId, room]);
            io.to(room).emit("message deleted", messageId);
        }
    });

    socket.on("clear chat", async (room) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const permissions = await getUserPermissions(nickname);
        if (permissions.clearChat) {
            await pool.query('DELETE FROM messages WHERE room = $1', [room]);
            io.to(room).emit("chat cleared");
        }
    });

    socket.on("mute user", async ({ room, targetUsername, duration }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const permissions = await getUserPermissions(nickname);
        if (permissions.muteUsers) {
            const targetSocketId = [...users.entries()].find(([_, name]) => name === targetUsername)?.[0];
            if (targetSocketId) {
                mutedUsers.set(targetSocketId, Date.now() + duration * 1000);
                io.to(room).emit("user muted", { nickname: targetUsername, duration });
            }
        }
    });

    socket.on("ban user", async ({ room, targetUsername }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const permissions = await getUserPermissions(nickname);
        if (permissions.banUsers) {
            const targetSocketId = [...users.entries()].find(([_, name]) => name === targetUsername)?.[0];
            if (targetSocketId) {
                users.delete(targetSocketId);
                await pool.query('DELETE FROM users WHERE nickname = $1', [targetUsername]);
                io.to(room).emit("user banned", targetUsername);
                const allUsers = await getAllUsers();
                const onlineUsers = Array.from(users.values());
                io.emit("update users", { 
                    users: await getAllUsers, 
                    onlineUsers,
                    onlineCount: onlineUsers.length, 
                    totalCount: (await getAllUsers()).length 
                });
                io.sockets.sockets.get(targetSocketId)?.disconnect();
            }
        }
    });

    socket.on("typing", (room) => {
        const nickname = users.get(socket.id);
        if (nickname) socket.to(room).emit("typing", nickname);
    });

    socket.on("stop typing", (room) => {
        socket.to(room).emit("stop typing");
    });

    socket.on("get profile", async (targetUsername) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const profile = await getUserProfile(targetUsername);
        if (profile) {
            const permissions = await getUserPermissions(nickname);
            socket.emit("profile data", { 
                ...profile, 
                isOwnProfile: nickname === targetUsername, 
                canAssignGroups: permissions.assignGroups 
            });
        } else {
            socket.emit("profile data", null);
        }
    });

    socket.on("update profile", async ({ avatar, age, bio }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        await updateUserProfile(nickname, { avatar, age, bio });
        socket.emit("profile updated", "Профиль обновлён");
    });

    socket.on("assign group", async ({ targetUsername, role }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        const permissions = await getUserPermissions(nickname);
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
                users: await getAllUsers, 
                onlineUsers,
                onlineCount: onlineUsers.length, 
                totalCount: (await getAllUsers()).length 
            });
        }
    });
});

http.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});