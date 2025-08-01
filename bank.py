# bank.py
import uvicorn
import requests
import os
import json
import sys
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder

import config
import crypto_utils

class KycSubmitPayload(BaseModel):
    verifiable_credential: dict

def setup_default_banks():
    """Generates keys for all default banks, registers with CA, and saves their certificate."""
    print("--- Setting up All Default Banks (if not already done) ---")
    for bank_id, bank_info in config.DEFAULT_BANKS.items():
        bank_key_file = f"{bank_id}_encrypted.key"
        bank_cert_file = f"{bank_id}.crt"
        if os.path.exists(bank_key_file) and os.path.exists(bank_cert_file):
            continue

        print(f"Setting up {bank_id}...")
        admin_password = bank_info['admin_password']
        signing_key, verify_key = crypto_utils.generate_did_keys()
        public_key_b64 = verify_key.encode(encoder=Base64Encoder).decode('utf-8')

        try:
            response = requests.post(f"{config.CA_URL}/register_bank", json={"id": bank_id, "public_key": public_key_b64})
            response.raise_for_status()
            
            response_data = response.json()
            bank_certificate = response_data.get("certificate")
            if bank_certificate:
                with open(bank_cert_file, 'w') as f:
                    f.write(bank_certificate)
                print(f"Certificate for {bank_id} received and saved.")
        except requests.exceptions.RequestException as e:
            print(f"Could not connect to CA to register {bank_id}. Is the CA server running?")
            return

        encrypted_key = crypto_utils.encrypt_data(signing_key.encode(), admin_password)
        with open(bank_key_file, 'wb') as f:
            f.write(encrypted_key)
    print("--- Default Bank Setup Complete ---")

app = FastAPI()

@app.post("/submit_kyc")
def submit_kyc(payload: KycSubmitPayload):
    vc = payload.verifiable_credential
    user_did = vc.get("issuer")
    bank_id = app.state.BANK_ID

    if not user_did:
        raise HTTPException(status_code=400, detail="VC is missing an issuer DID.")
        
    print(f"\nReceived KYC Verifiable Credential from issuer: {user_did}")
    
    try:
        print(f"--> Authenticating to CA to fetch public key for {user_did}...")
        
        bank_info = config.DEFAULT_BANKS[bank_id]
        admin_password = bank_info['admin_password']
        bank_key_file = f"{bank_id}_encrypted.key"
        
        with open(bank_key_file, 'rb') as f:
            encrypted_signing_key = f.read()
        bank_signing_key_bytes = crypto_utils.decrypt_data(encrypted_signing_key, admin_password)
        bank_signing_key = SigningKey(bank_signing_key_bytes)
        
        signature_for_ca = crypto_utils.sign_message(user_did, bank_signing_key)
        
        auth_payload = {
            "bank_id": bank_id,
            "target_user_did": user_did,
            "signature_hex": signature_for_ca
        }
        response = requests.post(f"{config.CA_URL}/get_key", json=auth_payload)
        response.raise_for_status()
        
        user_public_key_b64 = response.json()['public_key']
        print("--> Public key fetched successfully after authentication.")

        print("--> Verifying credential signature...")
        is_valid = crypto_utils.verify_credential(vc.copy(), user_public_key_b64)

        if is_valid:
            print("\n--- SIGNATURE VALID ---")
            print("Verified KYC Data:")
            print(json.dumps(vc['credentialSubject'], indent=2))
            print("--- KYC Verification Approved ---\n")
            return {"status": "success", "message": "KYC data verified and approved."}
        else:
            print("\n--- !!! SIGNATURE INVALID !!! ---")
            raise HTTPException(status_code=400, detail="Invalid credential signature.")
            
    except requests.exceptions.RequestException as e:
        print(f"!!! Error communicating with CA: {e.response.json() if e.response else e} !!!")
        raise HTTPException(status_code=500, detail="Error communicating with CA.")
    except Exception as e:
        print(f"!!! An unexpected error occurred: {e} !!!")
        raise HTTPException(status_code=500, detail="Internal server error during verification.")

def run_bank_server(bank_id: str):
    if bank_id not in config.DEFAULT_BANKS:
        print(f"Error: Bank '{bank_id}' is not defined in config.py.")
        return

    app.state.BANK_ID = bank_id
    port = config.DEFAULT_BANKS[bank_id]['port']

    print(f"--- Starting server for {bank_id} on port {port} ---")
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    setup_default_banks()
    
    if len(sys.argv) > 1:
        bank_to_run = sys.argv[1]
        run_bank_server(bank_to_run)
    else:
        print("\nTo run a bank server, provide the bank ID as an argument.")
        print(f"Example: python bank.py HDFC_BANK")