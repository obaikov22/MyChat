const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Подключаемся к PostgreSQL (замени URL на свой из Render)
const pool = new Pool({
    connectionString: "postgresql://chat_user:ta0SjNKfaOEUiWgoKPXAWMp58PfuxUFb@dpg-cusu4qdumphs73ccucu0-a/chat_9oa7", // Вставь Internal Database URL из Render
    ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
    if (err) {
        console.error("Ошибка подключения к PostgreSQL:", err.message);
    } else {
        console.log("Подключено к PostgreSQL");
    }
});

// Создаём таблицы
pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        nickname TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
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
        type TEXT NOT NULL
    )
`, (err) => {
    if (err) console.error("Ошибка создания таблицы messages:", err.message);
    else console.log("Таблица messages готова");
});

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/index.html");
});

app.use("/emoji-picker", express.static(path.join(__dirname, "node_modules/emoji-picker-element")));

const rooms = ["room1", "room2"];
const users = new Map(); // Активные пользователи (socket.id -> nickname)
const mutedUsers = new Map();
const blacklistedNicknames = [
    "administrator", "админ", "moderator", "модератор", "root", "superuser"
].map(name => name.toLowerCase());

const adminPassword = "MySecretPassword123";
const MAX_MESSAGES = 100;
const JWT_SECRET = "MySecretPassword123"; // Секретный ключ для JWT (замени на свой)

function generateToken(nickname) {
    return jwt.sign({ nickname }, JWT_SECRET, { expiresIn: "10m" }); // Токен на 10 минут
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

async function updateUserList() {
    try {
        const allUsersRes = await pool.query(`SELECT nickname FROM users`);
        const allUsers = allUsersRes.rows.map(row => row.nickname);
        console.log("Все пользователи из базы:", allUsers);

        const onlineUsers = Array.from(users.values());
        console.log("Онлайн пользователи:", onlineUsers);

        const userList = allUsers.sort((a, b) => {
            const aOnline = onlineUsers.includes(a);
            const bOnline = onlineUsers.includes(b);
            return bOnline - aOnline;
        });
        console.log("Отсортированный список:", userList);

        io.emit("update users", {
            users: userList,
            onlineCount: onlineUsers.length,
            totalCount: allUsers.length
        });
        console.log(`Отправлено: онлайн ${onlineUsers.length}/${allUsers.length}`);
    } catch (err) {
        console.error("Ошибка обновления списка пользователей:", err.message);
    }
}

async function saveMessage({ room, username, msg, timestamp, messageId, replyTo, type }) {
    try {
        await pool.query(
            `INSERT INTO messages (room, username, msg, timestamp, message_id, reply_to, type) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [room, username, msg, timestamp, messageId, replyTo || null, type]
        );
        console.log("Сообщение сохранено");

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
            type: row.type
        }));
    } catch (err) {
        console.error("Ошибка загрузки истории:", err.message);
        return [];
    }
}

io.on("connection", (socket) => {
    console.log("Пользователь подключился:", socket.id);

    updateUserList();

    socket.on("register", async ({ nickname, password }) => {
        console.log(`Регистрация: ${nickname}`);
        const trimmedNickname = nickname.trim();
        const lowerNickname = trimmedNickname.toLowerCase();

        if (!trimmedNickname || !password) {
            socket.emit("auth error", "Ник и пароль обязательны");
            return;
        }

        if (blacklistedNicknames.includes(lowerNickname) && lowerNickname !== "admin") {
            socket.emit("auth error", "Этот никнейм запрещён");
            return;
        }

        try {
            const res = await pool.query(`SELECT * FROM users WHERE nickname = $1`, [trimmedNickname]);
            if (res.rows.length > 0) {
                socket.emit("auth error", "Этот никнейм уже зарегистрирован, используйте вход");
            } else {
                const hashedPassword = await bcrypt.hash(password, 10);
                await pool.query(
                    `INSERT INTO users (nickname, password) VALUES ($1, $2)`,
                    [trimmedNickname, hashedPassword]
                );
                users.set(socket.id, trimmedNickname);
                const token = generateToken(trimmedNickname);
                socket.emit("auth success", { nickname: trimmedNickname, token });
                console.log(`Пользователь ${trimmedNickname} успешно зарегистрирован`);
                updateUserList();
            }
        } catch (err) {
            console.error("Ошибка регистрации:", err.message);
            socket.emit("auth error", "Ошибка сервера");
        }
    });

    socket.on("login", async ({ nickname, password }) => {
        console.log(`Вход: ${nickname}`);
        const trimmedNickname = nickname.trim();
        const lowerNickname = trimmedNickname.toLowerCase();

        if (!trimmedNickname || !password) {
            socket.emit("auth error", "Ник и пароль обязательны");
            return;
        }

        try {
            const res = await pool.query(`SELECT * FROM users WHERE nickname = $1`, [trimmedNickname]);
            if (res.rows.length === 0) {
                socket.emit("auth error", "Этот никнейм не зарегистрирован");
            } else {
                const match = await bcrypt.compare(password, res.rows[0].password);
                if (match) {
                    if (Array.from(users.values()).includes(trimmedNickname)) {
                        socket.emit("auth error", "Этот никнейм уже используется");
                    } else {
                        users.set(socket.id, trimmedNickname);
                        const token = generateToken(trimmedNickname);
                        socket.emit("auth success", { nickname: trimmedNickname, token });
                        console.log(`${trimmedNickname} вошёл`);
                        updateUserList();
                    }
                } else {
                    socket.emit("auth error", "Неверный пароль");
                }
            }
        } catch (err) {
            console.error("Ошибка входа:", err.message);
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
                socket.emit("auth success", { nickname, token });
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

            const history = await getChatHistory(room);
            socket.emit("chat history", history);
        }
    });

    socket.on("chat message", async ({ room, msg, replyTo }) => {
        const username = users.get(socket.id);
        if (!username) return;

        const isMuted = mutedUsers.has(socket.id) && mutedUsers.get(socket.id) > Date.now();
        if (isMuted) {
            socket.emit("muted", "Вы не можете отправлять сообщения, так как находитесь в муте");
            return;
        }

        const timestamp = new Date().toLocaleTimeString();
        const messageId = Date.now() + "-" + Math.random().toString(36).substr(2, 9);
        const messageData = { room, username, msg, timestamp, messageId, replyTo, type: "message" };

        if (username.toLowerCase() === "admin" && msg.startsWith("/add ")) {
            const announcement = msg.slice(5).trim();
            if (announcement) {
                messageData.msg = announcement;
                messageData.type = "announcement";
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
        if (username) io.to(room).emit("typing", username);
    });

    socket.on("stop typing", (room) => {
        io.to(room).emit("stop typing");
    });

    socket.on("delete message", async ({ room, messageId }) => {
        if (users.get(socket.id)?.toLowerCase() === "admin") {
            io.to(room).emit("message deleted", messageId);
            try {
                await pool.query(`DELETE FROM messages WHERE message_id = $1`, [messageId]);
                console.log(`Сообщение ${messageId} удалено`);
            } catch (err) {
                console.error("Ошибка удаления сообщения:", err.message);
            }
        }
    });

    socket.on("clear chat", async (room) => {
        if (users.get(socket.id)?.toLowerCase() === "admin") {
            io.to(room).emit("chat cleared");
            try {
                await pool.query(`DELETE FROM messages WHERE room = $1`, [room]);
                console.log(`Чат в комнате ${room} очищен`);
            } catch (err) {
                console.error("Ошибка очистки чата:", err.message);
            }
        }
    });

    socket.on("mute user", ({ room, targetUsername, duration }) => {
        if (users.get(socket.id)?.toLowerCase() !== "admin") return;
        const targetSocketId = Array.from(users.entries())
            .find(([_, name]) => name.toLowerCase() === targetUsername.toLowerCase())?.[0];
        if (targetSocketId) {
            const muteEnd = Date.now() + duration * 1000;
            mutedUsers.set(targetSocketId, muteEnd);
            io.to(room).emit("user muted", { username: targetUsername, duration });
        }
    });

    socket.on("ban user", ({ room, targetUsername }) => {
        if (users.get(socket.id)?.toLowerCase() !== "admin") return;
        const targetSocketId = Array.from(users.entries())
            .find(([_, name]) => name.toLowerCase() === targetUsername.toLowerCase())?.[0];
        if (targetSocketId) {
            io.to(room).emit("user banned", targetUsername);
            const targetSocket = io.sockets.sockets.get(targetSocketId);
            if (targetSocket) targetSocket.disconnect(true);
        }
    });

    socket.on("disconnect", () => {
        const username = users.get(socket.id);
        const currentRooms = Array.from(socket.rooms).filter(r => r !== socket.id);
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