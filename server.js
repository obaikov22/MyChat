const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 2e7, // Увеличиваем до 20 МБ
    pingTimeout: 60000,     // Увеличиваем таймаут до 60 секунд
    pingInterval: 25000     // Интервал проверки соединения
});

const pool = new Pool({
    connectionString: "postgresql://chat_user:ta0SjNKfaOEUiWgoKPXAWMp58PfuxUFb@dpg-cusu4qdumphs73ccucu0-a/chat_9oa7",
    ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
    if (err) console.error("Ошибка подключения к PostgreSQL:", err.message);
    else console.log("Подключено к PostgreSQL");
});

pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        nickname TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatar TEXT,
        age INTEGER,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        bio TEXT,
        is_main_admin BOOLEAN DEFAULT FALSE
    )
`, (err) => {
    if (err) console.error("Ошибка создания таблицы users:", err.message);
    else console.log("Таблица users готова");
});

pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        room TEXT NOT NULL,
        username TEXT NOT NULL,
        msg TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        message_id TEXT NOT NULL,
        reply_to TEXT,
        type TEXT NOT NULL,
        media TEXT
    )
`, (err) => {
    if (err) console.error("Ошибка создания таблицы messages:", err.message);
    else console.log("Таблица messages готова");
});

pool.query(`
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS media TEXT
`, (err) => {
    if (err) console.error("Ошибка добавления колонки media:", err.message);
    else console.log("Колонка media добавлена или уже существует");
});

pool.query(`
    CREATE TABLE IF NOT EXISTS groups (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        permissions JSONB NOT NULL
    )
`, (err) => {
    if (err) console.error("Ошибка создания таблицы groups:", err.message);
    else console.log("Таблица groups готова");
});

pool.query(`
    CREATE TABLE IF NOT EXISTS user_groups (
        user_id INTEGER REFERENCES users(id),
        group_id INTEGER REFERENCES groups(id),
        PRIMARY KEY (user_id, group_id)
    )
`, (err) => {
    if (err) console.error("Ошибка создания таблицы user_groups:", err.message);
    else console.log("Таблица user_groups готова");
});

pool.query(`
    CREATE TABLE IF NOT EXISTS achievements (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        achievement_name TEXT NOT NULL
    )
`, (err) => {
    if (err) console.error("Ошибка создания таблицы achievements:", err.message);
    else console.log("Таблица achievements готова");
});

async function initializeGroups() {
    const groups = [
        { name: "Администратор", permissions: { deleteMessages: true, clearChat: true, muteUsers: true, banUsers: true, assignGroups: false } },
        { name: "Модератор", permissions: { deleteMessages: false, clearChat: false, muteUsers: true, banUsers: true, assignGroups: false } }
    ];
    for (const group of groups) {
        await pool.query(
            `INSERT INTO groups (name, permissions) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`,
            [group.name, JSON.stringify(group.permissions)]
        );
    }
    console.log("Группы инициализированы");
}
initializeGroups();

app.get("/", (req, res) => res.sendFile(__dirname + "/index.html"));
app.use("/emoji-picker", express.static(path.join(__dirname, "node_modules/emoji-picker-element")));

const rooms = ["room1", "room2"];
const users = new Map();
const mutedUsers = new Map();
const blacklistedNicknames = ["administrator", "админ", "moderator", "модератор", "root", "superuser"].map(name => name.toLowerCase());

const MAX_MESSAGES = 100;
const JWT_SECRET = "MySecretPassword123";
const MAIN_ADMIN_NICKNAME = "Admin";

function generateToken(nickname) {
    return jwt.sign({ nickname }, JWT_SECRET, { expiresIn: "1d" });
}

async function verifyToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded.nickname;
    } catch (err) {
        console.error("Неверный или истёкший токен:", err.message);
        return null;
    }
}

async function getUserPermissions(nickname) {
    const userRes = await pool.query(`SELECT is_main_admin FROM users WHERE nickname = $1`, [nickname]);
    if (userRes.rows[0]?.is_main_admin) {
        return { deleteMessages: true, clearChat: true, muteUsers: true, banUsers: true, assignGroups: true };
    }

    const groupRes = await pool.query(`
        SELECT g.permissions FROM groups g
        JOIN user_groups ug ON g.id = ug.group_id
        JOIN users u ON u.id = ug.user_id
        WHERE u.nickname = $1
    `, [nickname]);

    let permissions = {};
    groupRes.rows.forEach(row => {
        Object.assign(permissions, row.permissions);
    });
    return permissions;
}

async function updateUserList() {
    try {
        const allUsersRes = await pool.query(`SELECT nickname, COALESCE(last_seen, CURRENT_TIMESTAMP) AS last_seen FROM users`);
        const allUsers = allUsersRes.rows.map(row => ({ nickname: row.nickname, last_seen: row.last_seen }));
        const onlineUsers = Array.from(users.values());
        const userList = allUsers.sort((a, b) => {
            const aOnline = onlineUsers.includes(a.nickname);
            const bOnline = onlineUsers.includes(b.nickname);
            return bOnline - aOnline;
        }).map(user => user.nickname);

        io.emit("update users", {
            users: userList,
            onlineCount: onlineUsers.length,
            totalCount: allUsers.length
        });
    } catch (err) {
        console.error("Ошибка обновления списка пользователей:", err.message);
    }
}

async function saveMessage({ room, username, msg, timestamp, messageId, replyTo, type, media }) {
    try {
        await pool.query(
            `INSERT INTO messages (room, username, msg, timestamp, message_id, reply_to, type, media) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [room, username, msg, timestamp, messageId, replyTo || null, type, media || null]
        );
        await pool.query(`
            DELETE FROM messages 
            WHERE room = $1 AND id NOT IN (
                SELECT id FROM messages 
                WHERE room = $1 
                ORDER BY id DESC 
                LIMIT ${MAX_MESSAGES}
            )`, [room]);
    } catch (err) {
        console.error("Ошибка сохранения сообщения:", err.message);
    }
}

async function getChatHistory(room, socketId) {
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
            media: row.media // Убрали canDelete
        }));
    } catch (err) {
        console.error("Ошибка загрузки истории:", err.message);
        return [];
    }
}

async function getUserProfile(nickname) {
    try {
        const userRes = await pool.query(
            `SELECT nickname, avatar, age, COALESCE(last_seen, CURRENT_TIMESTAMP) AS last_seen, bio FROM users WHERE nickname = $1`,
            [nickname]
        );
        const achievementsRes = await pool.query(
            `SELECT achievement_name FROM achievements WHERE user_id = (SELECT id FROM users WHERE nickname = $1)`,
            [nickname]
        );
        const groupsRes = await pool.query(`
            SELECT g.name FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            JOIN users u ON u.id = ug.user_id
            WHERE u.nickname = $1
        `, [nickname]);
        if (userRes.rows.length === 0) return null;
        return {
            nickname: userRes.rows[0].nickname,
            avatar: userRes.rows[0].avatar || "default-avatar.png",
            age: userRes.rows[0].age,
            last_seen: userRes.rows[0].last_seen,
            bio: userRes.rows[0].bio || "",
            achievements: achievementsRes.rows.map(row => row.achievement_name),
            groups: groupsRes.rows.map(row => row.name)
        };
    } catch (err) {
        console.error("Ошибка получения профиля:", err.message);
        return null;
    }
}

io.on("connection", (socket) => {
    console.log("Пользователь подключился:", socket.id);
    updateUserList();

    socket.on("auth", async ({ nickname, password }) => {
        const trimmedNickname = nickname.trim();
        const lowerNickname = trimmedNickname.toLowerCase();

        const trimmedPassword = password.trim();

        try {
            const databaseUsers = (await pool.query(`SELECT * FROM users WHERE nickname = $1`, [trimmedNickname])).rows;
            const isUserFound = databaseUsers.length > 0;

            if (!isUserFound) {
                if (blacklistedNicknames.includes(lowerNickname)) {
                    socket.emit("auth error", "Этот никнейм запрещён");
                    return;
                }

                const hashedPassword = await bcrypt.hash(trimmedPassword, 10);
                const isMainAdmin = trimmedNickname === MAIN_ADMIN_NICKNAME;
                await pool.query(
                    `INSERT INTO users (nickname, password, last_seen, is_main_admin) VALUES ($1, $2, CURRENT_TIMESTAMP, $3)`,
                    [trimmedNickname, hashedPassword, isMainAdmin]
                );
                users.set(socket.id, trimmedNickname);
                const token = generateToken(trimmedNickname);
                const permissions = await getUserPermissions(trimmedNickname);
                socket.emit("auth success", { nickname: trimmedNickname, token, permissions });
                console.log(`Пользователь ${trimmedNickname} успешно зарегистрирован`);
                updateUserList();
            } else {
                const [databaseUser] = databaseUsers;

                const userMatch = await bcrypt.compare(trimmedPassword, databaseUser.password);
                if (userMatch) {
                    if (Array.from(users.values()).includes(trimmedNickname)) {
                        socket.emit("auth error", "Пользователь уже в сети");
                    } else {
                        users.set(socket.id, trimmedNickname);
                        await pool.query(`UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE nickname = $1`, [trimmedNickname]);
                        const token = generateToken(trimmedNickname);
                        const permissions = await getUserPermissions(trimmedNickname);
                        socket.emit("auth success", { nickname: trimmedNickname, token, permissions });
                        console.log(`${trimmedNickname} вошёл`);
                        updateUserList();
                    }
                } else {
                    socket.emit("auth error", "Неверный пароль");
                } 
            }
        } catch (error) {
            console.error("Ошибка авторизации:", error.message);
            socket.emit("auth error", "Ошибка сервера");
        }
    });

    socket.on("auto login", async (token) => {
        const nickname = await verifyToken(token);
        if (nickname) {
            if (Array.from(users.values()).includes(nickname)) {
                socket.emit("auth error", "Этот никнейм уже используется");
            } else {
                users.set(socket.id, nickname);
                await pool.query(`UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE nickname = $1`, [nickname]);
                const permissions = await getUserPermissions(nickname);
                socket.emit("auth success", { nickname, token, permissions });
                console.log(`${nickname} вошёл автоматически`);
                updateUserList();
            }
        } else {
            socket.emit("auth error", "Токен недействителен или истёк");
        }
    });

    socket.on("join room", async (room) => {
        if (rooms.includes(room) && users.has(socket.id)) {
            const currentRooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const oldRoom = currentRooms.length ? currentRooms[0] : null;
            if (oldRoom) {
                socket.leave(oldRoom);
                console.log(`${users.get(socket.id)} покинул ${oldRoom}`);
            }
            socket.join(room);
            console.log(`${users.get(socket.id)} присоединился к ${room}`);
            updateUserList();
            const history = await getChatHistory(room, socket.id);
            socket.emit("chat history", history);
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
            media // Убрали canDelete из объекта сообщения
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

    socket.on("typing", (room) => {
        const username = users.get(socket.id);
        if (username) socket.to(room).emit("typing", username);
    });

    socket.on("stop typing", (room) => {
        socket.to(room).emit("stop typing");
    });

    socket.on("delete message", async ({ room, messageId }) => {
        const username = users.get(socket.id);
        const permissions = await getUserPermissions(username);
        if (permissions.deleteMessages) {
            io.to(room).emit("message deleted", messageId);
            try {
                await pool.query(`DELETE FROM messages WHERE message_id = $1`, [messageId]);
                console.log(`Сообщение ${messageId} удалено`);
            } catch (err) {
                console.error("Ошибка удаления сообщения:", err.message);
            }
        } else {
            socket.emit("auth error", "У вас нет прав на удаление сообщений");
        }
    });

    socket.on("clear chat", async (room) => {
        const username = users.get(socket.id);
        const permissions = await getUserPermissions(username);
        if (permissions.clearChat) {
            io.to(room).emit("chat cleared");
            try {
                await pool.query(`DELETE FROM messages WHERE room = $1`, [room]);
                console.log(`Чат в комнате ${room} очищен`);
            } catch (err) {
                console.error("Ошибка очистки чата:", err.message);
            }
        } else {
            socket.emit("auth error", "У вас нет прав на очистку чата");
        }
    });

    socket.on("mute user", async ({ room, targetUsername, duration }) => {
        const username = users.get(socket.id);
        const permissions = await getUserPermissions(username);
        if (permissions.muteUsers) {
            const targetSocketId = Array.from(users.entries())
                .find(([_, name]) => name.toLowerCase() === targetUsername.toLowerCase())?.[0];
            if (targetSocketId) {
                const muteEnd = Date.now() + duration * 1000;
                mutedUsers.set(targetSocketId, muteEnd);
                io.to(room).emit("user muted", { username: targetUsername, duration });
            }
        } else {
            socket.emit("auth error", "У вас нет прав на мут пользователей");
        }
    });

    socket.on("ban user", async ({ room, targetUsername }) => {
        const username = users.get(socket.id);
        const permissions = await getUserPermissions(username);
        if (permissions.banUsers) {
            const targetSocketId = Array.from(users.entries())
                .find(([_, name]) => name.toLowerCase() === targetUsername.toLowerCase())?.[0];
            if (targetSocketId) {
                io.to(room).emit("user banned", targetUsername);
                const targetSocket = io.sockets.sockets.get(targetSocketId);
                if (targetSocket) targetSocket.disconnect(true);
            }
        } else {
            socket.emit("auth error", "У вас нет прав на бан пользователей");
        }
    });

    socket.on("get profile", async (targetUsername) => {
        const profile = await getUserProfile(targetUsername);
        if (profile) {
            const isOwnProfile = users.get(socket.id) === targetUsername;
            const permissions = await getUserPermissions(users.get(socket.id));
            socket.emit("profile data", { ...profile, isOwnProfile, canAssignGroups: permissions.assignGroups });
        } else {
            socket.emit("auth error", "Пользователь не найден");
        }
    });

    socket.on("update profile", async ({ avatar, age, bio }) => {
        const nickname = users.get(socket.id);
        if (!nickname) return;
        try {
            await pool.query(
                `UPDATE users SET avatar = $1, age = $2, bio = $3 WHERE nickname = $4`,
                [avatar || null, age || null, bio || null, nickname]
            );
            socket.emit("profile updated", "Профиль обновлён");
            console.log(`Профиль ${nickname} обновлён`);
            updateUserList();
        } catch (err) {
            console.error("Ошибка обновления профиля:", err.message);
            socket.emit("auth error", "Ошибка обновления профиля");
        }
    });

    socket.on("assign group", async ({ targetUsername, groupName }) => {
        const username = users.get(socket.id);
        const permissions = await getUserPermissions(username);
        if (!permissions.assignGroups) {
            socket.emit("auth error", "У вас нет прав на назначение групп");
            return;
        }
        try {
            const groupRes = await pool.query(`SELECT id FROM groups WHERE name = $1`, [groupName]);
            if (groupRes.rows.length === 0) {
                socket.emit("auth error", "Группа не найдена");
                return;
            }
            const groupId = groupRes.rows[0].id;
            const userRes = await pool.query(`SELECT id FROM users WHERE nickname = $1`, [targetUsername]);
            if (userRes.rows.length === 0) {
                socket.emit("auth error", "Пользователь не найден");
                return;
            }
            const userId = userRes.rows[0].id;
            await pool.query(
                `INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
                [userId, groupId]
            );
            socket.emit("group assigned", `${targetUsername} назначена группа ${groupName}`);
            console.log(`${username} назначил ${targetUsername} группу ${groupName}`);
            updateUserList();
        } catch (err) {
            console.error("Ошибка назначения группы:", err.message);
            socket.emit("auth error", "Ошибка назначения группы");
        }
    });

    socket.on("disconnect", () => {
        const username = users.get(socket.id);
        if (username) {
            pool.query(`UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE nickname = $1`, [username]);
        }
        users.delete(socket.id);
        mutedUsers.delete(socket.id);
        console.log(`${username} отключился`);
        updateUserList();
    });
});

process.on("SIGINT", () => {
    pool.end(() => {
        console.log("Соединение с PostgreSQL закрыто");
        process.exit(0);
    });
});

server.listen(3000, () => {
    console.log("Сервер запущен на http://localhost:3000");
});