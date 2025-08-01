# config.py
# Central configuration for the project

HOST = "http://localhost"
CA_PORT = 5000
BANK_PORT_START = 5001 # We will assign ports dynamically

# List of default banks to pre-configure
DEFAULT_BANKS = {
    "HDFC_BANK": {"port": 5001, "admin_password": "admin_password_hdfc"},
    "ICICI_BANK": {"port": 5002, "admin_password": "admin_password_icici"},
    "SBI_BANK": {"port": 5003, "admin_password": "admin_password_sbi"},
}

CA_URL = f"{HOST}:{CA_PORT}"

# Database file for the CA
CA_DB_FILE = "ca_database.db"