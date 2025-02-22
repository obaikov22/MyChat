const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const db = new sqlite3.Database("./chat.db", (err) => {
    if (err) {
        console.error("Ошибка подключения к базе данных:", err.message);
    } else {
        console.log("Подключено к базе данных SQLite");
    }
});

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
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
});

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

const adminPassword = "MySecretPassword123";
const MAX_MESSAGES = 100;

function updateRoomUsers(room) {
    const roomUsers = Array.from(io.sockets.adapter.rooms.get(room) || [])
        .map(socketId => users.get(socketId))
        .filter(username => username);
    io.to(room).emit("update users", roomUsers);
    console.log(`Обновлён список пользователей в ${room}: ${roomUsers}`);
}

function saveMessage({ room, username, msg, timestamp, messageId, replyTo, type }, callback) {
    db.run(
        `INSERT INTO messages (room, username, msg, timestamp, messageId, replyTo, type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [room, username, msg, timestamp, messageId, replyTo || null, type],
        (err) => {
            if (err) {
                console.error("Ошибка сохранения сообщения:", err.message);
                callback(err);
            } else {
                db.run(`
                    DELETE FROM messages 
                    WHERE room = ? AND id NOT IN (
                        SELECT id FROM messages 
                        WHERE room = ? 
                        ORDER BY id DESC 
                        LIMIT ${MAX_MESSAGES}
                    )`,
                    [room, room],
                    (err) => {
                        if (err) console.error("Ошибка удаления старых сообщений:", err.message);
                        callback(null);
                    }
                );
            }
        }
    );
}

function getChatHistory(room, callback) {
    db.all(`
        SELECT * FROM messages 
        WHERE room = ? 
        ORDER BY id ASC 
        LIMIT ${MAX_MESSAGES}`,
        [room],
        (err, rows) => {
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
        }
    );
}

io.on("connection", (socket) => {
    console.log("Пользователь подключился:", socket.id);

    socket.on("register", ({ nickname, password }) => {
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

        db.get(`SELECT * FROM users WHERE nickname = ?`, [trimmedNickname], (err, row) => {
            if (err) {
                console.error("Ошибка проверки ника:", err.message);
                socket.emit("auth error", "Ошибка сервера");
                return;
            }

            if (row) {
                socket.emit("auth error", "Этот никнейм уже зарегистрирован, используйте вход");
            } else {
                bcrypt.hash(password, 10, (err, hashedPassword) => {
                    if (err) {
                        console.error("Ошибка хеширования пароля:", err.message);
                        socket.emit("auth error", "Ошибка сервера");
                        return;
                    }

                    db.run(
                        `INSERT INTO users (nickname, password) VALUES (?, ?)`,
                        [trimmedNickname, hashedPassword],
                        (err) => {
                            if (err) {
                                console.error("Ошибка регистрации:", err.message);
                                socket.emit("auth error", "Ошибка сервера");
                            } else {
                                users.set(socket.id, trimmedNickname);
                                socket.emit("auth success", trimmedNickname);
                                console.log(`Зарегистрирован ${trimmedNickname}`);
                            }
                        }
                    );
                });
            }
        });
    });

    socket.on("login", ({ nickname, password }) => {
        console.log(`Вход: ${nickname}`);
        const trimmedNickname = nickname.trim();
        const lowerNickname = trimmedNickname.toLowerCase();

        if (!trimmedNickname || !password) {
            socket.emit("auth error", "Ник и пароль обязательны");
            return;
        }

        db.get(`SELECT * FROM users WHERE nickname = ?`, [trimmedNickname], (err, row) => {
            if (err) {
                console.error("Ошибка проверки ника:", err.message);
                socket.emit("auth error", "Ошибка сервера");
                return;
            }

            if (!row) {
                socket.emit("auth error", "Этот никнейм не зарегистрирован");
            } else {
                bcrypt.compare(password, row.password, (err, match) => {
                    if (err) {
                        console.error("Ошибка проверки пароля:", err.message);
                        socket.emit("auth error", "Ошибка сервера");
                        return;
                    }

                    if (match) {
                        if (Array.from(users.values()).includes(trimmedNickname)) {
                            socket.emit("auth error", "Этот никнейм уже используется");
                        } else {
                            users.set(socket.id, trimmedNickname);
                            socket.emit("auth success", trimmedNickname);
                            console.log(`${trimmedNickname} вошёл`);
                        }
                    } else {
                        socket.emit("auth error", "Неверный пароль");
                    }
                });
            }
        });
    });

    socket.on("join room", (room) => {
        if (rooms.includes(room) && users.has(socket.id)) {
            const currentRooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const oldRoom = currentRooms.length ? currentRooms[0] : null;

            if (oldRoom) {
                socket.leave(oldRoom);
                console.log(`${users.get(socket.id)} покинул ${oldRoom}`);
                updateRoomUsers(oldRoom);
            }

            socket.join(room);
            console.log(`${users.get(socket.id)} присоединился к ${room}`);
            updateRoomUsers(room);

            getChatHistory(room, (history) => {
                socket.emit("chat history", history);
            });
        }
    });

    socket.on("chat message", ({ room, msg, replyTo }) => {
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
                saveMessage(messageData, (err) => {
                    if (!err) console.log("Объявление сохранено");
                });
            }
            return;
        }

        io.to(room).emit("chat message", messageData);
        saveMessage(messageData, (err) => {
            if (!err) console.log("Сообщение сохранено");
        });
    });

    socket.on("typing", (room) => {
        const username = users.get(socket.id);
        if (username) io.to(room).emit("typing", username);
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
        if (users.get(socket.id)?.toLowerCase() === "admin") return;
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