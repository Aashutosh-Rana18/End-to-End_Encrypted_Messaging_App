# 🔐 End-to-End Encrypted Messaging App

### Project by Aashutosh Rana  
📅 October 2025

---

## 🧭 Overview

The End-to-End Encrypted Messaging App is a secure real-time chat system designed to keep user conversations completely private.  
It provides instant messaging features similar to modern chat apps like WhatsApp but with true end-to-end encryption (E2EE).  
Messages are encrypted and decrypted only on the client side, ensuring that no third party — not even the server — can read them.

---

## 🎯 Objective

The goal of this project is to create a secure communication platform that:

- Maintains user privacy through end-to-end encryption.  
- Uses RSA public-key cryptography for key exchange.  
- Uses AES-GCM symmetric encryption for message confidentiality.  
- Ensures the server stores only encrypted data, never plaintext messages.

---

## ⚙️ Technologies Used

| Component | Technology |
|------------|-------------|
| Frontend | React (optional UI with animations) or Python Terminal Client |
| Backend | Python (Flask + Flask-SocketIO) |
| Encryption | RSA (for key exchange), AES-GCM (for message encryption) |
| Libraries | flask, flask-socketio, python-socketio, eventlet, websocket-client, cryptography |
| Storage | Encrypted chat logs (encrypted_logs.jsonl) |
| Styling (Web UI) | Tailwind CSS + Framer Motion (for optional frontend) |

---

## 🧩 Working Process

1. **RSA Key Generation**  
   Each user generates a unique RSA public-private key pair locally.  
   Only the public key is shared with the server; the private key remains on the client.

2. **Public Key Exchange**  
   The server stores user public keys so they can be fetched for message encryption.

3. **Message Encryption**  
   - The sender generates a random 256-bit AES key.  
   - The message is encrypted using AES-GCM with that key.  
   - The AES key is encrypted using the recipient’s RSA public key.

4. **Transmission**  
   The encrypted AES key, nonce, and ciphertext are sent to the server via Socket.IO.

5. **Decryption (Client-Side)**  
   The recipient decrypts the AES key with their RSA private key, then decrypts the message.

6. **Encrypted Logs (Optional)**  
   The server stores the encrypted message payload in a `.jsonl` log file for record-keeping, without any ability to decrypt them.

---

## 🔐 Security Highlights

- True End-to-End Encryption: Only sender and receiver can view plaintext.  
- RSA-OAEP Padding: Used for secure AES key transmission.  
- AES-GCM Encryption: Provides both confidentiality and integrity.  
- Local Key Generation: No private keys ever leave the client.  
- Encrypted Logs: The server never sees unencrypted messages.

---

## 🧠 Features

✅ Real-time messaging using Flask-SocketIO  
✅ Hybrid RSA + AES encryption scheme  
✅ Local RSA key generation for every user  
✅ Encrypted message storage on server  
✅ Simple command-line interface  
✅ Extendable React-based GUI for modern look and feel  

---

## 🏗️ Project Structure

secure-chat-app/

│

├── server.py # Flask-SocketIO server

├── client.py # Python client (E2EE terminal chat)

├── crypto_utils.py # RSA & AES encryption utilities

├── encrypted_logs.jsonl # Optional encrypted logs stored by server

├── End-to-End_Encrypted_Messaging_App_Report_Aashutosh_Rana.pdf

└── README.md # Documentation file

---

## 🚀 Setup Instructions

### 1️⃣ Install Dependencies
pip install flask flask-socketio python-socketio eventlet websocket-client cryptography


### 2️⃣ Start the Server
python server.py
You should see:

Server initialized for eventlet

### 3️⃣ Run Clients
Open two separate terminals and run:
python client.py alice
python client.py bob

Both users will connect to the same server and exchange public keys automatically.

### 4️⃣ Send Encrypted Messages
From Alice’s terminal:
msg bob Hello Bob!

On Bob’s terminal:
From alice: Hello Bob!
✅ Message successfully sent, encrypted, and decrypted.


## 🧰 Example of Encrypted Log Entry

Sample from `encrypted_logs.jsonl`:
{
"ts": 1730202104.89,
"from": "alice",
"to": "bob",
"enc_key": "BASE64ENCODED_AES_KEY",
"nonce": "BASE64ENCODED_NONCE",
"ciphertext": "BASE64ENCODED_MESSAGE"
}

The server cannot decrypt this message.

---

## 🧾 Security Guidelines

- Always use HTTPS/WSS for production deployment.  
- Never transmit private keys or store them on the server.  
- Verify public key fingerprints out-of-band for authenticity.  
- Rotate RSA keys periodically for long-term sessions.  
- Use secure OS-level key storage for private keys.

---

## 💡 Future Enhancements

- 🌐 Browser-based client using React + WebCrypto API  
- 🔁 Forward secrecy via Diffie–Hellman or X25519  
- 📞 Encrypted voice/video calls  
- ☁️ Multi-device synchronization  
- 🧱 User authentication and key verification interface  

---

## 📚 References

- Flask-SocketIO Documentation  
- Python Cryptography Library  
- RSA Standard: PKCS#1 v2.2 (RFC 8017)  
- NIST AES-GCM Recommendation: SP 800-38D  
- Project Report: *End-to-End Encrypted Messaging App Report – Aashutosh Rana (2025)*

---

## 👨‍💻 Author

**Aashutosh Rana**  
Student Developer | Cybersecurity & Web Technologies  
📍 India | 📅 October 2025  

> "Privacy is not an option, and it shouldn’t be the price we accept for just getting on the Internet."  
> — Gary Kovacs
