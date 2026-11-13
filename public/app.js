
import sodium from "https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.15/+esm";

const socket = io();

const messages = document.getElementById("messages");
const form = document.getElementById("message-form");
const input = document.getElementById("message-input");
const status = document.getElementById("status");

let keyPair;
const peers = new Map();

function showMessage(text, type) {
  const welcome = messages.querySelector(".welcome");
  if (welcome) welcome.remove();

  const message = document.createElement("div");
  message.className = `message ${type}`;
  message.textContent = text;

  messages.appendChild(message);
  messages.scrollTop = messages.scrollHeight;
}

async function initializeEncryption() {
  await sodium.ready;

  keyPair = sodium.crypto_box_keypair();

  // Share only the public key with the server and other users.
  socket.emit(
    "public-key",
    sodium.to_base64(keyPair.publicKey)
  );

  status.textContent = "Connected — encryption initialized";
}

socket.on("connect", () => {
  status.textContent = "Connected — initializing encryption...";
  initializeEncryption().catch((error) => {
    console.error(error);
    status.textContent = "Encryption initialization failed";
  });
});

socket.on("disconnect", () => {
  status.textContent = "Disconnected";
});

socket.on("peer-public-key", ({ socketId, publicKey }) => {
  try {
    const decodedKey = sodium.from_base64(publicKey);
    peers.set(socketId, decodedKey);
    showMessage("A user joined the chat.", "received");
  } catch (error) {
    console.error("Invalid public key:", error);
  }
});

socket.on("peer-left", (socketId) => {
  peers.delete(socketId);
  showMessage("A user left the chat.", "received");
});

socket.on("encrypted-message", (data) => {
  try {
    const senderPublicKey = peers.get(data.senderId);

    if (!senderPublicKey || !keyPair) return;

    const nonce = sodium.from_base64(data.nonce);
    const ciphertext = sodium.from_base64(data.ciphertext);

    const plaintext = sodium.crypto_box_open_easy(
      ciphertext,
      nonce,
      senderPublicKey,
      keyPair.privateKey
    );

    const message = sodium.to_string(plaintext);
    showMessage(message, "received");
  } catch (error) {
    console.error("Message decryption failed:", error);
    showMessage("Unable to decrypt a received message.", "received");
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const message = input.value.trim();

  if (!message || !keyPair) return;

  if (peers.size === 0) {
    alert("Open CipherChat in another browser window to chat.");
    return;
  }

  const plaintext = sodium.from_string(message);

  for (const [recipientId, recipientPublicKey] of peers) {
    const nonce = sodium.randombytes_buf(
      sodium.crypto_box_NONCEBYTES
    );

    const ciphertext = sodium.crypto_box_easy(
      plaintext,
      nonce,
      recipientPublicKey,
      keyPair.privateKey
    );

    socket.emit("encrypted-message", {
      recipientId,
      senderId: socket.id,
      nonce: sodium.to_base64(nonce),
      ciphertext: sodium.to_base64(ciphertext)
    });
  }

  showMessage(message, "sent");
  input.value = "";
});