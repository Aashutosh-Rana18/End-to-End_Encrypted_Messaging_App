import sys, json, threading, time
import socketio
from crypto_utils import *
import os

SERVER = "http://127.0.0.1:5000"

sio = socketio.Client()

# Simple local key storage
KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

def get_key_paths(username):
    return os.path.join(KEY_DIR, f"{username}_priv.pem"), os.path.join(KEY_DIR, f"{username}_pub.pem")

def ensure_keys(username):
    priv_path, pub_path = get_key_paths(username)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path,'rb') as f: priv = load_private_key(f.read())
        with open(pub_path,'rb') as f: pub = load_public_key(f.read())
        return priv, pub
    priv, pub = generate_rsa_keypair()
    with open(priv_path,'wb') as f: f.write(private_key_to_pem(priv))
    with open(pub_path,'wb') as f: f.write(public_key_to_pem(pub))
    return priv, pub

def register_username(username, pub_pem):
    sio.emit('register', {'username': username, 'public_key_pem': pub_pem.decode('utf-8')})

@sio.event
def connect():
    print("[connected to server]")

@sio.on('connected')
def on_connected(d):
    pass

@sio.on('register_response')
def on_register_response(d):
    print("Register response:", d)

@sio.on('users')
def on_users(d):
    print("Online users:", d.get('users', []))

@sio.on('public_key')
def on_public_key(d):
    # triggered when client asked for someone else's public key
    print("Public key reply:", d)

@sio.on('incoming_message')
def on_incoming_message(payload):
    # payload: from,to,enc_key (b64), nonce (b64), ciphertext (b64)
    print("\n[Encrypted message received]")
    sender = payload['from']
    enc_key = ub64(payload['enc_key'])
    nonce = ub64(payload['nonce'])
    ciphertext = ub64(payload['ciphertext'])

    # load my private key to decrypt AES key
    privkey, _ = ensure_keys(USERNAME)
    try:
        aes_key = rsa_decrypt(privkey, enc_key)
        plaintext = aesgcm_decrypt(aes_key, nonce, ciphertext)
        print(f"From {sender}: {plaintext.decode('utf-8')}")
    except Exception as e:
        print("Decryption failed:", e)

@sio.on('send_status')
def on_send_status(d):
    print("[send status]", d)

def interactive_loop():
    while True:
        line = input("\nEnter command (msg <user> <text> / getkey <user> / quit):\n> ").strip()
        if not line: continue
        if line == 'quit':
            sio.disconnect()
            break
        parts = line.split(' ', 2)
        if parts[0] == 'getkey' and len(parts) >= 2:
            target = parts[1]
            sio.emit('get_public_key', {'username': target})
        elif parts[0] == 'msg' and len(parts) == 3:
            target, text = parts[1], parts[2]
            send_encrypted_message(USERNAME, target, text)
        else:
            print("Unknown command.")

def send_encrypted_message(sender, recipient, text):
    got = {}
    def handler(d):
        got['data']=d
    sio.on('public_key', handler)
    sio.emit('get_public_key', {'username': recipient})
    # wait up to 3 seconds for public key
    for _ in range(30):
        if 'data' in got: break
        time.sleep(0.1)
    if 'data' not in got or not got['data'].get('ok'):
        print("Could not fetch public key for", recipient)
        return
    pub_pem = got['data']['public_key_pem'].encode('utf-8')
    recipient_pub = load_public_key(pub_pem)

    # create AES key and encrypt message
    aes_key = os.urandom(32)  # 256-bit
    nonce, ciphertext = aesgcm_encrypt(aes_key, text.encode('utf-8'))
    enc_key = rsa_encrypt(recipient_pub, aes_key)

    payload = {
        'from': sender,
        'to': recipient,
        'enc_key': b64(enc_key),
        'nonce': b64(nonce),
        'ciphertext': b64(ciphertext)
    }
    sio.emit('private_message', payload)
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)
    USERNAME = sys.argv[1]
    priv, pub = ensure_keys(USERNAME)
    sio.connect(SERVER)
    register_username(USERNAME, public_key_to_pem(pub))
    try:
        interactive_loop()
    except KeyboardInterrupt:
        sio.disconnect()
