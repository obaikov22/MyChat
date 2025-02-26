const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Настройка Express
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "https://mychat-ap.onrender.com",
        methods: ["GET", "POST"]
    }
});

// Настройка папки для загружаемых файлов (медиа)
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Список пользователей (в памяти, можно заменить на БД, например MongoDB)
const users = {};
const rooms = {
    room1: { messages: [], users: new Set() },
    room2: { messages: [], users: new Set() }
};
const privateMessages = {};
const bans = new Set();
const mutes = {}; // { nickname: { until: timestamp } }

// Middleware
app.use(express.json());
app.use(express.static('public')); // Доступ к статическим файлам (index.html, uploads)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Маршруты
app.post('/login', (req, res) => {
    const { nickname, password } = req.body;
    if (!nickname || !password) {
        return res.json({ success: false, message: 'Введите никнейм и пароль' });
    }

    if (bans.has(nickname)) {
        return res.json({ success: false, message: 'Вы забанены' });
    }

    if (users[nickname] && users[nickname].password === password) {
        if (mutes[nickname] && Date.now() < mutes[nickname].until) {
            return res.json({ success: false, message: `Вы заглушены до ${new Date(mutes[nickname].until).toLocaleTimeString()}` });
        }
        res.json({ success: true, nickname, permissions: users[nickname].permissions || {} });
    } else {
        res.json({ success: false, message: 'Неверный никнейм или пароль' });
    }
});

app.post('/register', (req, res) => {
    const { nickname, password } = req.body;
    if (!nickname || !password) {
        return res.json({ success: false, message: 'Введите никнейм и пароль' });
    }

    if (users[nickname]) {
        return res.json({ success: false, message: 'Никнейм уже занят' });
    }

    users[nickname] = { password, permissions: {} }; // Простая авторизация, можно добавить роли/права
    res.json({ success: true, message: 'Регистрация успешна' });
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Файл не загружен' });
    }
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ success: true, url: fileUrl });
});

app.post('/update-profile', (req, res) => {
    const { nickname, age, bio } = req.body;
    if (!nickname || !users[nickname]) {
        return res.json({ success: false, message: 'Пользователь не найден' });
    }
    users[nickname].age = age || users[nickname].age;
    users[nickname].bio = bio || users[nickname].bio;
    res.json({ success: true, profile: { nickname, age: users[nickname].age, bio: users[nickname].bio, avatar: users[nickname].avatar || '/default-avatar.png', status: 'online', achievements: [] } });
});

// Socket.IO обработчики
io.on('connection', (socket) => {
    let currentRoom = 'room1';
    let currentUser = null;

    socket.on('login', (data, callback) => {
        const { nickname, password } = data;
        if (users[nickname] && users[nickname].password === password) {
            if (bans.has(nickname)) {
                callback({ success: false, message: 'Вы забанены' });
                return;
            }
            if (mutes[nickname] && Date.now() < mutes[nickname].until) {
                callback({ success: false, message: `Вы заглушены до ${new Date(mutes[nickname].until).toLocaleTimeString()}` });
                return;
            }
            currentUser = nickname;
            users[nickname].socketId = socket.id;
            socket.join(currentRoom);
            rooms[currentRoom].users.add(nickname);
            callback({ success: true, nickname, permissions: users[nickname].permissions || {} });
            io.to(currentRoom).emit('update users', { users: Object.values(users), onlineUsers: Array.from(rooms[currentRoom].users), onlineCount: rooms[currentRoom].users.size, totalCount: Object.keys(users).length, room: currentRoom });
            socket.emit('avatar', { avatar: users[nickname].avatar || '/default-avatar.png' });
        } else {
            callback({ success: false, message: 'Неверный никнейм или пароль' });
        }
    });

    socket.on('register', (data, callback) => {
        const { nickname, password } = data;
        if (users[nickname]) {
            callback({ success: false, message: 'Никнейм уже занят' });
        } else {
            users[nickname] = { password, permissions: {} };
            callback({ success: true });
        }
    });

    socket.on('join room', (room) => {
        if (currentUser && rooms[room]) {
            socket.leave(currentRoom);
            rooms[currentRoom].users.delete(currentUser);
            socket.join(room);
            currentRoom = room;
            rooms[room].users.add(currentUser);
            io.to(currentRoom).emit('update users', { users: Object.values(users), onlineUsers: Array.from(rooms[room].users), onlineCount: rooms[room].users.size, totalCount: Object.keys(users).length, room });
            socket.emit('chat history', getPaginatedHistory(room, 1, 50));
        }
    });

    socket.on('leave room', (room) => {
        if (currentUser && rooms[room]) {
            socket.leave(room);
            rooms[room].users.delete(currentUser);
            io.to(room).emit('update users', { users: Object.values(users), onlineUsers: Array.from(rooms[room].users), onlineCount: rooms[room].users.size, totalCount: Object.keys(users).length, room });
        }
    });

    socket.on('leave private chat', () => {
        if (currentUser) {
            socket.leave('private-' + currentUser);
        }
    });

    socket.on('chat message', (messageData) => {
        if (!currentUser || (mutes[currentUser] && Date.now() < mutes[currentUser].until)) return;
        const { room, msg, replyTo, media } = messageData;
        if (rooms[room]) {
            const message = {
                type: 'message',
                nickname: currentUser,
                msg,
                timestamp: new Date().toLocaleTimeString(),
                messageId: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
                replyTo,
                media,
                avatar: users[currentUser]?.avatar || '/default-avatar.png'
            };
            rooms[room].messages.push(message);
            if (rooms[room].messages.length > 1000) rooms[room].messages.shift(); // Ограничение на 1000 сообщений
            io.to(room).emit('chat message', message);
            socket.emit('typing', { nickname: currentUser, room });
        }
    });

    socket.on('announcement', (messageData) => {
        if (!currentUser || !userPermissions[currentUser]?.isAdmin) return;
        const { room, msg, replyTo, media } = messageData;
        if (rooms[room]) {
            const message = {
                type: 'announcement',
                nickname: currentUser,
                msg,
                timestamp: new Date().toLocaleTimeString(),
                messageId: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
                replyTo,
                media,
                avatar: users[currentUser]?.avatar || '/default-avatar.png'
            };
            rooms[room].messages.push(message);
            if (rooms[room].messages.length > 1000) rooms[room].messages.shift();
            io.to(room).emit('announcement', message);
        }
    });

    socket.on('get chat history', ({ room, page, limit }, callback) => {
        if (rooms[room]) {
            callback(getPaginatedHistory(room, page, limit));
        }
    });

    function getPaginatedHistory(room, page, limit) {
        const start = (page - 1) * limit;
        const end = start + limit;
        return rooms[room].messages.slice().reverse().slice(start, end);
    }

    socket.on('mute user', (data) => {
        if (!currentUser || !userPermissions[currentUser]?.muteUsers) return;
        const { nickname, duration } = data;
        if (users[nickname] && !bans.has(nickname)) {
            mutes[nickname] = { until: Date.now() + duration };
            io.emit('user muted', { nickname, duration });
            if (users[nickname].socketId) {
                io.to(users[nickname].socketId).emit('muted', `Вы заглушены на ${duration / 1000} секунд`);
            }
        }
    });

    socket.on('ban user', (nickname) => {
        if (!currentUser || !userPermissions[currentUser]?.banUsers) return;
        if (users[nickname]) {
            bans.add(nickname);
            if (users[nickname].socketId) {
                io.to(users[nickname].socketId).emit('banned');
                io.to(users[nickname].socketId).disconnect(true);
            }
            io.emit('user banned', { nickname });
        }
    });

    socket.on('mute all', (room) => {
        if (!currentUser || !userPermissions[currentUser]?.muteUsers) return;
        if (rooms[room]) {
            rooms[room].users.forEach(user => {
                if (!bans.has(user)) {
                    mutes[user] = { until: Date.now() + 300000 }; // 5 минут
                    if (users[user]?.socketId) {
                        io.to(users[user].socketId).emit('muted', 'Вы заглушены на 5 минут');
                    }
                }
            });
            io.to(room).emit('user muted', { nickname: 'Все', duration: 300000 });
        }
    });

    socket.on('ban all', (room) => {
        if (!currentUser || !userPermissions[currentUser]?.banUsers) return;
        if (rooms[room]) {
            rooms[room].users.forEach(user => {
                bans.add(user);
                if (users[user]?.socketId) {
                    io.to(users[user].socketId).emit('banned');
                    io.to(users[user].socketId).disconnect(true);
                }
            });
            io.to(room).emit('user banned', { nickname: 'Все' });
        }
    });

    socket.on('delete message', (data) => {
        if (!currentUser || !userPermissions[currentUser]?.deleteMessages) return;
        const { messageId, room } = data;
        if (rooms[room]) {
            rooms[room].messages = rooms[room].messages.filter(msg => msg.messageId !== messageId);
            io.to(room).emit('message deleted', messageId);
        }
    });

    socket.on('send private message', (data) => {
        if (!currentUser || (mutes[currentUser] && Date.now() < mutes[currentUser].until)) return;
        const { recipientNickname, message } = data;
        if (users[recipientNickname]) {
            const pmKey = [currentUser, recipientNickname].sort().join('-');
            if (!privateMessages[pmKey]) privateMessages[pmKey] = [];
            const pmMessage = {
                senderNickname: currentUser,
                recipientNickname,
                message,
                timestamp: new Date().toLocaleTimeString(),
                read: false,
                messageId: Date.now() + '-' + Math.random().toString(36).substr(2, 9)
            };
            privateMessages[pmKey].push(pmMessage);
            if (privateMessages[pmKey].length > 1000) privateMessages[pmKey].shift();
            if (users[recipientNickname].socketId) {
                io.to(users[recipientNickname].socketId).emit('new private message', pmMessage);
            }
            socket.emit('private message sent', { recipientNickname });
            updatePMCountForUser(recipientNickname);
        } else {
            socket.emit('private message error', 'Пользователь не найден');
        }
    });

    socket.on('get private message history', (recipientNickname, callback) => {
        if (!currentUser || !users[recipientNickname]) {
            callback([]);
            return;
        }
        const pmKey = [currentUser, recipientNickname].sort().join('-');
        callback(privateMessages[pmKey] || []);
    });

    socket.on('mark private message as read', (recipientNickname) => {
        if (!currentUser || !users[recipientNickname]) return;
        const pmKey = [currentUser, recipientNickname].sort().join('-');
        if (privateMessages[pmKey]) {
            privateMessages[pmKey].forEach(msg => {
                if (!msg.read && msg.senderNickname === recipientNickname) {
                    msg.read = true;
                }
            });
        }
        updatePMCountForUser(currentUser);
    });

    socket.on('get unread pm count', (callback) => {
        if (!currentUser) {
            callback(0);
            return;
        }
        let count = 0;
        for (let key in privateMessages) {
            if (key.includes(currentUser)) {
                privateMessages[key].forEach(msg => {
                    if (!msg.read && msg.recipientNickname === currentUser) {
                        count++;
                    }
                });
            }
        }
        callback(count);
    });

    socket.on('get all users for pm', (callback) => {
        callback(Object.values(users).map(user => ({
            nickname: user.nickname || user,
            avatar: user.avatar || '/default-avatar.png',
            status: users[user.socketId] ? 'online' : 'offline'
        })));
    });

    socket.on('get user profile', (nickname, callback) => {
        if (users[nickname]) {
            callback({
                nickname,
                status: users[users[nickname]?.socketId] ? 'online' : 'offline',
                age: users[nickname].age || 'Не указан',
                bio: users[nickname].bio || 'Биография не указана',
                avatar: users[nickname].avatar || '/default-avatar.png',
                achievements: [] // Можно расширить в БД
            });
        } else {
            callback(null);
        }
    });

    socket.on('update profile', (data, callback) => {
        const { nickname, age, bio } = data;
        if (users[nickname] && currentUser === nickname) {
            users[nickname].age = age || users[nickname].age;
            users[nickname].bio = bio || users[nickname].bio;
            callback({ success: true, profile: { nickname, age: users[nickname].age, bio: users[nickname].bio, avatar: users[nickname].avatar || '/default-avatar.png', status: 'online', achievements: [] } });
            io.emit('profile updated', { nickname, age: users[nickname].age, bio: users[nickname].bio, avatar: users[nickname].avatar || '/default-avatar.png', status: 'online', achievements: [] });
        } else {
            callback({ success: false, message: 'Ошибка обновления профиля' });
        }
    });

    socket.on('typing', (data) => {
        const { room } = data;
        if (currentUser && rooms[room]) {
            io.to(room).emit('typing', { nickname: currentUser });
        }
    });

    socket.on('disconnect', () => {
        if (currentUser) {
            rooms[currentRoom].users.delete(currentUser);
            io.to(currentRoom).emit('update users', { users: Object.values(users), onlineUsers: Array.from(rooms[currentRoom].users), onlineCount: rooms[currentRoom].users.size, totalCount: Object.keys(users).length, room: currentRoom });
            delete users[currentUser].socketId;
        }
    });
});

function updatePMCountForUser(nickname) {
    if (users[nickname]?.socketId) {
        let count = 0;
        for (let key in privateMessages) {
            if (key.includes(nickname)) {
                privateMessages[key].forEach(msg => {
                    if (!msg.read && msg.recipientNickname === nickname) {
                        count++;
                    }
                });
            }
        }
        io.to(users[nickname].socketId).emit('unread pm count', count);
    }
}

// Запуск сервера
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});