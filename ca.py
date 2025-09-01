# ca.py
import uvicorn
import sqlite3
import os
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
import uuid
from datetime import timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import config
import crypto_utils

# Create the FastAPI app first
app = FastAPI()

CA_KEY_FILE = "ca_master_encrypted.key"
CA_CERT_FILE = "ca_master_cert.pem"
CA_PASSWORD = "ca_master_password"

class RegisterPayload(BaseModel):
    id: str
    public_key: str

class AuthenticatedGetKeyPayload(BaseModel):
    bank_id: str
    target_user_did: str
    signature_hex: str

class RevocationPayload(BaseModel):
    credential_id: str
    issuer_did: str
    signature_hex: str

def setup_database():
    """Initializes the database and creates tables if they don't exist."""
    conn = sqlite3.connect(config.CA_DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            entity_type TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS revoked_credentials (
            credential_id TEXT PRIMARY KEY,
            revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def setup_ca_identity():
    """Creates the CA's own master key pair and self-signed certificate if they don't exist."""
    if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        return

    print("--- First-time setup for CA master identity ---")
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    
    private_key_bytes = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_key = crypto_utils.encrypt_data(private_key_bytes, CA_PASSWORD)
    with open(CA_KEY_FILE, 'wb') as f:
        f.write(encrypted_key)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyIdea CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"myidea-ca.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("CA master key and self-signed certificate created.")

def create_bank_certificate(bank_id: str, bank_public_key_b64: str):
    """Creates and signs a certificate for a bank using the CA's master key."""
    with open(CA_KEY_FILE, 'rb') as f:
        encrypted_key = f.read()
    ca_private_key_bytes = crypto_utils.decrypt_data(encrypted_key, CA_PASSWORD)
    ca_private_key = serialization.load_pem_private_key(ca_private_key_bytes, password=None)

    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Note: Bank public key is Ed25519, which can't go in a standard X.509 cert.
    # For this academic purpose, we'll create a dummy RSA key to put in the cert.
    # A real system would use a different certificate profile (e.g., CVC).
    dummy_bank_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Registered Banks"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{bank_id}.myidea-banks.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        dummy_bank_key.public_key() # Using dummy key for compatibility
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=730)
    ).sign(ca_private_key, hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

@app.on_event("startup")
def on_startup():
    setup_database()
    setup_ca_identity()
    print("Database and CA Identity setup complete.")

@app.post("/register")
def register_entity(payload: RegisterPayload):
    try:
        conn = sqlite3.connect(config.CA_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO entities (id, public_key, entity_type) VALUES (?, ?, 'user')", 
                       (payload.id, payload.public_key))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "message": f"User '{payload.id}' registered."}

@app.post("/register_bank")
def register_bank(payload: RegisterPayload):
    try:
        conn = sqlite3.connect(config.CA_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO entities (id, public_key, entity_type) VALUES (?, ?, 'bank')", 
                       (payload.id, payload.public_key))
        conn.commit()
    finally:
        conn.close()
    
    print(f"Issuing certificate for bank: {payload.id}")
    bank_certificate_pem = create_bank_certificate(payload.id, payload.public_key)
    
    return {
        "status": "success", 
        "message": f"Bank '{payload.id}' registered.",
        "certificate": bank_certificate_pem
    }

@app.post("/get_key")
def get_key(payload: AuthenticatedGetKeyPayload):
    conn = sqlite3.connect(config.CA_DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT public_key FROM entities WHERE id = ?", (payload.bank_id,))
    bank_result = cursor.fetchone()
    if not bank_result:
        raise HTTPException(status_code=404, detail=f"Requesting bank '{payload.bank_id}' not found.")
    
    bank_public_key_b64 = bank_result[0]
    bank_verify_key = VerifyKey(bank_public_key_b64, encoder=Base64Encoder)
    
    message_to_verify = payload.target_user_did
    is_bank_signature_valid = crypto_utils.verify_message_signature(
        message=message_to_verify,
        signature_hex=payload.signature_hex,
        verify_key=bank_verify_key
    )

    if not is_bank_signature_valid:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid signature from bank.")

    cursor.execute("SELECT public_key FROM entities WHERE id = ?", (payload.target_user_did,))
    user_result = cursor.fetchone()
    conn.close()
    
    if user_result:
        return {"status": "success", "public_key": user_result[0]}
    
    raise HTTPException(status_code=404, detail=f"Target user '{payload.target_user_did}' not found.")

@app.post("/revoke_credential")
def revoke_credential(payload: RevocationPayload):
    """Allows an issuer to revoke a credential."""
    try:
        # Verify the issuer's signature
        conn = sqlite3.connect(config.CA_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM entities WHERE id = ?", (payload.issuer_did,))
        issuer_result = cursor.fetchone()
        
        if not issuer_result:
            raise HTTPException(status_code=404, detail="Issuer not found.")
            
        issuer_public_key_b64 = issuer_result[0]
        issuer_verify_key = VerifyKey(issuer_public_key_b64, encoder=Base64Encoder)
        
        message_to_verify = f"revoke:{payload.credential_id}"
        is_signature_valid = crypto_utils.verify_message_signature(
            message=message_to_verify,
            signature_hex=payload.signature_hex,
            verify_key=issuer_verify_key
        )
        
        if not is_signature_valid:
            raise HTTPException(status_code=403, detail="Invalid signature.")
        
        # Add to revocation list
        cursor.execute("INSERT OR REPLACE INTO revoked_credentials (credential_id) VALUES (?)", 
                       (payload.credential_id,))
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": f"Credential {payload.credential_id} revoked."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/credentials/status/{credential_id}")
def check_credential_status(credential_id: str):
    """Checks if a credential has been revoked."""
    try:
        conn = sqlite3.connect(config.CA_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM revoked_credentials WHERE credential_id = ?", (credential_id,))
        revoked = cursor.fetchone() is not None
        conn.close()
        
        return {"revoked": revoked}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print(f"CA starting on port {config.CA_PORT}")
    uvicorn.run("ca:app", host="0.0.0.0", port=config.CA_PORT, reload=True)