
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;
const publicKeys = new Map();

app.use(express.static(path.join(__dirname, "public")));

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("public-key", (publicKey) => {
    // Send existing users' public keys to the new user.
    for (const [socketId, key] of publicKeys) {
      socket.emit("peer-public-key", {
        socketId,
        publicKey: key
      });
    }

    // Store the new user's public key.
    publicKeys.set(socket.id, publicKey);

    // Share the new user's public key with existing users.
    socket.broadcast.emit("peer-public-key", {
      socketId: socket.id,
      publicKey
    });
  });

  socket.on("encrypted-message", (data) => {
    if (
      !data ||
      data.senderId !== socket.id ||
      typeof data.recipientId !== "string" ||
      typeof data.nonce !== "string" ||
      typeof data.ciphertext !== "string"
    ) {
      return;
    }

    // Relay ciphertext only. The server cannot decrypt it.
    io.to(data.recipientId).emit("encrypted-message", data);
  });

  socket.on("disconnect", () => {
    publicKeys.delete(socket.id);
    socket.broadcast.emit("peer-left", socket.id);
    console.log("User disconnected:", socket.id);
  });
});

server.listen(PORT, () => {
  console.log(`CipherChat running at http://localhost:${PORT}`);
});