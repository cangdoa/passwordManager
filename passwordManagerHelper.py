import json
import sys
from pathlib import Path
import os
import base64
import time
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

BACK = "back"
HELP = "?"
ADD = "add"
REMOVE = "remove"
SERVICES = "services"
UPDATE = "update"
RETRIEVE = "retrieve"
EXIT = "exit"
DELETE = "delete"

if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

hasher = PasswordHasher()

FILE_NAME = BASE_DIR / "passwords.json"

def retrieve_json():
    if Path(FILE_NAME).exists():
        with open(FILE_NAME, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}
    
def retrieve_user(email):
    all_users = retrieve_json()
    return all_users[email]

def find_user(email):
    all_users = retrieve_json()
    return email in all_users

def check_passkey(email, passkey):
    user = retrieve_user(email)
    try:
        hasher.verify(user["passkey"], passkey)
        return True
    except:
        return False

def new_user(email, passkey):
    new_user = {}
    new_user["passkey"] = hasher.hash(passkey)
    salt = os.urandom(16)
    new_user["salt"] = base64.b64encode(salt).decode()
    new_user.setdefault("accounts", {})
    write_to_json(new_user, False, email)


def write_to_json(current_user, deleted, email):
    all_users = retrieve_json()
    all_users[email] = current_user
    if deleted:
        del all_users[email]
    with open(FILE_NAME, "w") as file:
        json.dump(all_users, file, indent = 2)

def check_service(email, added_service):
    user = retrieve_user(email)
    added_service = added_service.lower()
    if added_service in user["accounts"]:
        return True
    else:
        return False

def add_service(email, added_service, passkey, password):
    user = retrieve_user(email)
    added_service = added_service.lower()
    encryption_key = derive_key(passkey, base64.b64decode(user["salt"]))
    user["accounts"][added_service] = encrypt_password(password, encryption_key)
    write_to_json(user, False, email)

def remove_service(email, removed_service):
    user = retrieve_user(email)
    del user["accounts"][removed_service]
    write_to_json(user, False, email)

def list_services(email, passkey):
    user = retrieve_user(email)
    ret_string = ""
    encryption_key = derive_key(passkey, base64.b64decode(user["salt"]))
    if not user["accounts"]:
        return "No services added to the database"
    for service in user["accounts"]:
        decrypted = decrypt_password(user["accounts"][service], encryption_key)
        ret_string += f"Service: {service.title()} - Password: {decrypted}\n"
    return ret_string

def derive_key(passkey, salt):
    kdf = Scrypt(
        salt = salt,
        length = 32,
        n = 2**14,
        r = 8,
        p = 1,
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_password(password, key):
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode()

def decrypt_password(password, key):
    f = Fernet(key)
    decrypted = f.decrypt(password.encode())
    return decrypted.decode()
