# user.py
import requests
import os
import json
import uuid
from getpass import getpass
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder

import config
import crypto_utils

USER_DATA_FILE = "multi_user_data_pairwise.json"
CURRENT_USER_SESSION = {}

def load_all_user_data():
    """Loads all user profiles from the JSON file."""
    if not os.path.exists(USER_DATA_FILE):
        return {}
    with open(USER_DATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_all_user_data(data):
    """Saves all user profiles to the JSON file."""
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def signup():
    """Signs up a new user with a username/password and generates a master DID."""
    print("--- Create a New User Account ---")
    username = input("Choose a username for login: ").lower()
    all_users = load_all_user_data()

    if username in all_users:
        print("Username already exists. Please choose another one.")
        return

    password = getpass("Set a strong master password: ")
    
    print("\nPlease provide your personal information for your secure vault.")
    full_name = input("Full Name: ")
    dob = input("Date of Birth (DD-MM-YYYY): ")
    pan_number = input("PAN Number: ").upper()
    personal_data = {"fullName": full_name, "dateOfBirth": dob, "pan": pan_number}

    # Generate a MASTER key pair and DID. This is the user's root identity.
    master_signing_key, master_verify_key = crypto_utils.generate_did_keys()
    master_did = crypto_utils.get_did_from_key(master_verify_key)
    print(f"Your private, master Decentralized ID (DID) has been generated.")

    encrypted_master_key = crypto_utils.encrypt_data(master_signing_key.encode(), password)
    encrypted_personal_data = crypto_utils.encrypt_data(json.dumps(personal_data).encode('utf-8'), password)
    
    all_users[username] = {
        'master_did': master_did,
        'encrypted_master_signing_key_hex': encrypted_master_key.hex(),
        'encrypted_personal_data_hex': encrypted_personal_data.hex(),
        'relationships': {} # This will store the pairwise DIDs for each bank
    }
    
    save_all_user_data(all_users)
    print(f"User '{username}' created successfully! Please log in.")

def login():
    """Logs in a user and sets up the session."""
    global CURRENT_USER_SESSION
    if CURRENT_USER_SESSION:
        print("You are already logged in. Please log out first.")
        return

    print("--- Login ---")
    username = input("Username: ").lower()
    password = getpass("Password: ")

    all_users = load_all_user_data()
    if username not in all_users:
        print("Username not found.")
        return

    user_data = all_users[username]
    try:
        # Verify password by trying to decrypt the master key
        encrypted_key = bytes.fromhex(user_data['encrypted_master_signing_key_hex'])
        crypto_utils.decrypt_data(encrypted_key, password)
        
        CURRENT_USER_SESSION = {
            "username": username,
            "password": password,
            "user_data": user_data
        }
        print(f"Login successful. Welcome, {username}!")
    except Exception:
        print("Invalid password.")

def logout():
    """Logs out the current user."""
    global CURRENT_USER_SESSION
    if not CURRENT_USER_SESSION:
        print("You are not logged in.")
        return
    
    print(f"Logging out {CURRENT_USER_SESSION['username']}...")
    CURRENT_USER_SESSION = {}
    print("Logout successful.")

def create_or_get_pairwise_did_for_bank(bank_id):
    """Creates a new, unique DID for a bank relationship if one doesn't exist."""
    username = CURRENT_USER_SESSION['username']
    password = CURRENT_USER_SESSION['password']
    all_users = load_all_user_data()
    user_data = all_users[username]
    
    # Check if we already have a pairwise DID for this bank
    if bank_id in user_data['relationships']:
        print(f"--> Using existing pairwise DID for {bank_id}.")
        return user_data['relationships'][bank_id]['pairwise_did']
        
    # If not, create a new one
    print(f"--> No relationship found with {bank_id}. Creating a new pairwise DID...")
    pairwise_signing_key, pairwise_verify_key = crypto_utils.generate_did_keys()
    pairwise_did = crypto_utils.get_did_from_key(pairwise_verify_key)
    print(f"--> Your new unique DID for {bank_id} is: {pairwise_did}")

    # Register the NEW pairwise DID and public key with the CA
    try:
        public_key_b64 = pairwise_verify_key.encode(encoder=Base64Encoder).decode('utf-8')
        response = requests.post(f"{config.CA_URL}/register", json={"id": pairwise_did, "public_key": public_key_b64})
        response.raise_for_status()
        print(f"--> CA Response: {response.json()['message']}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to CA: {e}")
        return None

    # Encrypt and save the new pairwise key
    encrypted_pairwise_key = crypto_utils.encrypt_data(pairwise_signing_key.encode(), password)
    
    # Update user data with the new relationship
    user_data['relationships'][bank_id] = {
        'pairwise_did': pairwise_did,
        'encrypted_pairwise_signing_key_hex': encrypted_pairwise_key.hex()
    }
    save_all_user_data(all_users)
    
    return pairwise_did

def verify_kyc():
    """Performs KYC using a unique pairwise DID for the selected bank."""
    if not CURRENT_USER_SESSION:
        print("You must be logged in to perform KYC.")
        return

    password = CURRENT_USER_SESSION['password']
    
    print(f"Available banks: {list(config.DEFAULT_BANKS.keys())}")
    bank_id = input("Enter the ID of the bank to verify with: ").upper()
    if bank_id not in config.DEFAULT_BANKS:
        print("Invalid Bank ID.")
        return

    print("\nStarting KYC process...")
    
    try:
        # 1. Get or create a unique pairwise DID for this bank
        pairwise_did = create_or_get_pairwise_did_for_bank(bank_id)
        if not pairwise_did:
            print("Failed to establish a pairwise relationship. Aborting.")
            return

        # 2. Get the keys and data needed for this transaction
        all_users = load_all_user_data()
        user_data = all_users[CURRENT_USER_SESSION['username']]
        relationship_data = user_data['relationships'][bank_id]

        encrypted_key_bytes = bytes.fromhex(relationship_data['encrypted_pairwise_signing_key_hex'])
        signing_key_bytes = crypto_utils.decrypt_data(encrypted_key_bytes, password)
        signing_key = SigningKey(signing_key_bytes)
        
        encrypted_personal_data_bytes = bytes.fromhex(user_data['encrypted_personal_data_hex'])
        personal_data_bytes = crypto_utils.decrypt_data(encrypted_personal_data_bytes, password)
        personal_data = json.loads(personal_data_bytes)

        # 3. Create a Verifiable Credential issued by the PAIRWISE DID
        print("--> Creating a signed Verifiable Credential...")
        verifiable_credential = crypto_utils.sign_credential(
            credential_subject=personal_data,
            user_did=pairwise_did, # IMPORTANT: The VC is issued by the pairwise DID
            signing_key=signing_key
        )
        print("--> Credential created and signed.")

        # 4. Present the Verifiable Credential to the Bank
        bank_port = config.DEFAULT_BANKS[bank_id]['port']
        bank_url = f"http://localhost:{bank_port}"
        
        print(f"--> Presenting credential to {bank_id}...")
        response = requests.post(f"{bank_url}/submit_kyc", json={"verifiable_credential": verifiable_credential})
        response.raise_for_status()

        print(f"-> Bank Final Response: {response.json()['message']}")
        print("\nKYC Process Completed Successfully!")

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

def main_menu():
    """Displays the main menu and handles user choices."""
    while True:
        print("\n" + "="*20)
        print("--- User Digital Vault ---")
        if CURRENT_USER_SESSION:
            print(f"Logged in as: {CURRENT_USER_SESSION['username']}")
            print("1. Verify KYC with a Bank")
            print("2. Logout")
        else:
            print("1. Signup (New User)")
            print("2. Login")
        
        print("3. Exit")
        print("="*20)
        choice = input("Select option: ").strip()

        if CURRENT_USER_SESSION:
            if choice == '1':
                verify_kyc()
            elif choice == '2':
                logout()
            elif choice == '3':
                break
        else:
            if choice == '1':
                signup()
            elif choice == '2':
                login()
            elif choice == '3':
                break

if __name__ == "__main__":
    main_menu()