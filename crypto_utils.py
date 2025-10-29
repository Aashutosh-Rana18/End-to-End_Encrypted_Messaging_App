import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# RSA key generation and serialization
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def private_key_to_pem(private_key, password:bytes = None):
    enc = (serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key(pem_bytes, password:bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)

def load_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

# RSA OAEP encryption/decryption for small payloads (AES key)
def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

# AES-GCM encrypt/decrypt (authenticated)
def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    # AESGCM returns ciphertext || tag. We'll send nonce and ct base64-encoded.
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

# helpers for base64 encoding used in network payloads
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))
