const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/index.html");
});

app.use("/emoji-picker", express.static(path.join(__dirname, "node_modules/emoji-picker-element")));

const rooms = ["room1", "room2"];
const users = new Map();
const mutedUsers = new Map();
const chatHistory = new Map(); // Храним историю для каждой комнаты
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

            // Отправляем историю чата новому пользователю
            if (chatHistory.has(room)) {
                socket.emit("chat history", chatHistory.get(room));
            }
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
        const messageData = { username, msg, timestamp, messageId, replyTo };

        if (username.toLowerCase() === "admin" && msg.startsWith("/add ")) {
            const announcement = msg.slice(5).trim();
            if (announcement) {
                messageData.msg = announcement;
                io.to(room).emit("announcement", messageData);
                if (!chatHistory.has(room)) chatHistory.set(room, []);
                chatHistory.get(room).push({ ...messageData, type: "announcement" });
            }
            return;
        }

        io.to(room).emit("chat message", messageData);
        if (!chatHistory.has(room)) chatHistory.set(room, []);
        chatHistory.get(room).push({ ...messageData, type: "message" });
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
            if (chatHistory.has(room)) {
                const history = chatHistory.get(room);
                const index = history.findIndex(msg => msg.messageId === messageId);
                if (index !== -1) history.splice(index, 1);
            }
        }
    });

    socket.on("clear chat", (room) => {
        if (users.get(socket.id)?.toLowerCase() === "admin") {
            io.to(room).emit("chat cleared");
            if (chatHistory.has(room)) chatHistory.set(room, []);
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

server.listen(3000, () => {
    console.log("Сервер запущен на http://localhost:3000");
});