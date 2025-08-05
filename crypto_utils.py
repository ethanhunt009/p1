# crypto_utils.py
# Shared cryptographic helper functions

import os
import json
import base58
from datetime import datetime, timezone
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder

# --- Symmetric Encryption for local storage ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypts data using a password-derived key with AES-GCM."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt_data(encrypted_blob: bytes, password: str) -> bytes:
    """Decrypts an AES-GCM encrypted blob using a password-derived key."""
    salt, nonce, ciphertext = encrypted_blob[:16], encrypted_blob[16:28], encrypted_blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- Asymmetric Cryptography for DIDs and VCs ---

def generate_did_keys():
    """Generates an Ed25519 key pair for creating a DID."""
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key

def get_did_from_key(verify_key: VerifyKey):
    """Generates a did:key from a public verification key."""
    prefixed_key = b'\xed\x01' + verify_key.encode()
    encoded_key = base58.b58encode(prefixed_key).decode('utf-8')
    return f"did:key:{encoded_key}"


def sign_credential(credential_subject: dict, user_did: str, signing_key: SigningKey):
    """Creates and signs a Verifiable Credential."""
    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "KYCCredential"],
        "issuer": user_did,
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "credentialSubject": credential_subject
    }
    
    message_to_sign = json.dumps(vc, sort_keys=True, separators=(',', ':')).encode('utf-8') 
    signed_data = signing_key.sign(message_to_sign)                                        #VC Hash generated here <-------
    
    vc['proof'] = {
        "type": "Ed25519Signature2018",
        "verificationMethod": user_did,
        "signatureValue": signed_data.signature.hex()
    }
    return vc

def verify_credential(vc: dict, public_key_b64: str):
    """Verifies the signature on a Verifiable Credential."""
    if 'proof' not in vc:
        return False
        
    proof = vc.pop('proof')
    signature_bytes = bytes.fromhex(proof['signatureValue'])
    message_to_verify = json.dumps(vc, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    try:
        verify_key = VerifyKey(public_key_b64, encoder=Base64Encoder)
        verify_key.verify(message_to_verify, signature_bytes)
        return True
    except Exception:
        return False

def sign_message(message: str, signing_key: SigningKey) -> str:
    """Signs a simple string message and returns the signature in hex."""
    return signing_key.sign(message.encode('utf-8')).signature.hex()

def verify_message_signature(message: str, signature_hex: str, verify_key: VerifyKey) -> bool:
    """Verifies a signature against a message."""
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        verify_key.verify(message.encode('utf-8'), signature_bytes)
        return True
    except Exception:
        return False