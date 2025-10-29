from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import json, os, time
from crypto_utils import public_key_to_pem, load_public_key
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret'  # change in production
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True)

USERS = {}  # username -> {'sid': socketid, 'pubkey_pem': str}
LOG_FILE = "encrypted_logs.jsonl"

def append_log(entry: dict):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

@socketio.on('connect')
def on_connect():
    print("Client connected:", request.sid)
    emit('connected', {'msg':'connected'})

@socketio.on('register')
def on_register(data):
    """
    data = { 'username': 'alice', 'public_key_pem': '-----BEGIN...' }
    """
    username = data.get('username')
    pub_pem = data.get('public_key_pem')
    if not username or not pub_pem:
        emit('register_response', {'ok': False, 'error': 'missing fields'})
        return
    # Basic load test
    try:
        load_public_key(pub_pem.encode('utf-8'))
    except Exception as e:
        emit('register_response', {'ok': False, 'error': 'invalid public key'})
        return
    USERS[username] = {'sid': request.sid, 'public_key_pem': pub_pem}
    print(f"Registered {username} with sid {request.sid}")
    emit('register_response', {'ok': True})
    # broadcast new user list
    socketio.emit('users', {'users': list(USERS.keys())})

@socketio.on('get_public_key')
def on_get_public_key(data):
    """
    request: { 'username': 'bob' }
    response: { 'ok': True, 'public_key_pem': '...' } or error
    """
    username = data.get('username')
    if username in USERS:
        emit('public_key', {'ok': True, 'username': username, 'public_key_pem': USERS[username]['public_key_pem']})
    else:
        emit('public_key', {'ok': False, 'error': 'user not found', 'username': username})

@socketio.on('private_message')
def on_private_message(payload):
    """
    payload expected keys:
      from, to, enc_key (b64), nonce (b64), ciphertext (b64)
    The server forwards to recipient. Server can optionally append encrypted log (payload)
    """
    required = ['from','to','enc_key','nonce','ciphertext']
    if not all(k in payload for k in required):
        emit('send_status', {'ok': False, 'error': 'missing fields'})
        return
    recipient = payload['to']
    # persist encrypted log (server stores only opaque payload)
    log_entry = {
        'ts': time.time(),
        'from': payload['from'],
        'to': recipient,
        'enc_key': payload['enc_key'],
        'nonce': payload['nonce'],
        'ciphertext': payload['ciphertext']
    }
    append_log(log_entry)
    # forward if online
    if recipient in USERS:
        sid = USERS[recipient]['sid']
        socketio.emit('incoming_message', payload, room=sid)
        emit('send_status', {'ok': True, 'delivered': True})
    else:
        emit('send_status', {'ok': True, 'delivered': False, 'message': 'recipient offline — saved to logs'})

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    remove = None
    for u,v in list(USERS.items()):
        if v['sid'] == sid:
            remove = u
            del USERS[u]
            break
    print("Disconnected", sid, "removed user:", remove)
    socketio.emit('users', {'users': list(USERS.keys())})

if __name__ == '__main__':
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()
    socketio.run(app, host='0.0.0.0', port=5000)
