const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Подключаем базу данных SQLite
const db = new sqlite3.Database("./chat.db", (err) => {
    if (err) {
        console.error("Ошибка подключения к базе данных:", err.message);
    } else {
        console.log("Подключено к базе данных SQLite");
    }
});

// Создаём таблицу сообщений, если её нет
db.run(`
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room TEXT NOT NULL,
        username TEXT NOT NULL,
        msg TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        messageId TEXT NOT NULL,
        replyTo TEXT,
        type TEXT NOT NULL
    )
`);

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/index.html");
});

app.use("/emoji-picker", express.static(path.join(__dirname, "node_modules/emoji-picker-element")));

const rooms = ["room1", "room2"];
const users = new Map();
const mutedUsers = new Map();
const blacklistedNicknames = [
    "administrator", "админ", "moderator", "модератор", "root", "superuser"
].map(name => name.toLowerCase());

const adminPassword = "MySecretPassword123"; // Замени на свой пароль

function updateRoomUsers(room) {
    const roomUsers = Array.from(io.sockets.sockets.values())
        .filter(s => s.rooms.has(room))
        .map(s => users.get(s.id));
    io.to(room).emit("update users", roomUsers);
}

function saveMessage({ room, username, msg, timestamp, messageId, replyTo, type }) {
    db.run(
        `INSERT INTO messages (room, username, msg, timestamp, messageId, replyTo, type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [room, username, msg, timestamp, messageId, replyTo || null, type],
        (err) => {
            if (err) console.error("Ошибка сохранения сообщения:", err.message);
        }
    );
}

function getChatHistory(room, callback) {
    db.all(`SELECT * FROM messages WHERE room = ?`, [room], (err, rows) => {
        if (err) {
            console.error("Ошибка загрузки истории:", err.message);
            callback([]);
        } else {
            callback(rows.map(row => ({
                username: row.username,
                msg: row.msg,
                timestamp: row.timestamp,
                messageId: row.messageId,
                replyTo: row.replyTo,
                type: row.type
            })));
        }
    });
}

io.on("connection", (socket) => {
    console.log("Пользователь подключился");

    socket.on("set username", ({ username, password }) => {
        const trimmedUsername = username.trim();
        const lowerUsername = trimmedUsername.toLowerCase();

        if (!trimmedUsername) {
            socket.emit("username error", "Никнейм не может быть пустым");
            return;
        }

        if (lowerUsername === "admin") {
            if (!password || password !== adminPassword) {
                socket.emit("admin password required");
                return;
            }
        } else if (blacklistedNicknames.includes(lowerUsername)) {
            socket.emit("username error", "Этот никнейм запрещён");
            return;
        }

        if (Array.from(users.values()).some(u => u.toLowerCase() === lowerUsername)) {
            socket.emit("username error", "Этот никнейм уже занят");
            return;
        }

        users.set(socket.id, trimmedUsername);
        socket.emit("username set", trimmedUsername);
        console.log(`Ник ${trimmedUsername} установлен для ${socket.id}`);
    });

    socket.on("join room", (room) => {
        if (rooms.includes(room)) {
            const currentRooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const oldRoom = currentRooms.length ? currentRooms[0] : null;

            if (oldRoom) {
                socket.leave(oldRoom);
                updateRoomUsers(oldRoom);
            }

            socket.join(room);
            console.log(`${users.get(socket.id)} присоединился к ${room}`);
            updateRoomUsers(room);

            // Отправляем историю чата из базы данных
            getChatHistory(room, (history) => {
                socket.emit("chat history", history);
            });
        }
    });

    socket.on("chat message", ({ room, msg, replyTo }) => {
        const username = users.get(socket.id);
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
                saveMessage(messageData);
            }
            return;
        }

        io.to(room).emit("chat message", messageData);
        saveMessage(messageData);
    });

    socket.on("typing", (room) => {
        const username = users.get(socket.id);
        io.to(room).emit("typing", username);
    });

    socket.on("stop typing", (room) => {
        io.to(room).emit("stop typing");
    });

    socket.on("delete message", ({ room, messageId }) => {
        if (users.get(socket.id)?.toLowerCase() === "admin") {
            io.to(room).emit("message deleted", messageId);
            db.run(`DELETE FROM messages WHERE messageId = ?`, [messageId], (err) => {
                if (err) console.error("Ошибка удаления сообщения:", err.message);
            });
        }
    });

    socket.on("clear chat", (room) => {
        if (users.get(socket.id)?.toLowerCase() === "admin") {
            io.to(room).emit("chat cleared");
            db.run(`DELETE FROM messages WHERE room = ?`, [room], (err) => {
                if (err) console.error("Ошибка очистки чата:", err.message);
            });
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
        currentRooms.forEach(room => updateRoomUsers(room));
    });
});

// Закрываем базу данных при завершении работы сервера
process.on("SIGINT", () => {
    db.close((err) => {
        if (err) console.error("Ошибка закрытия базы данных:", err.message);
        console.log("База данных закрыта");
        process.exit(0);
    });
});

server.listen(3000, () => {
    console.log("Сервер запущен на http://localhost:3000");
});