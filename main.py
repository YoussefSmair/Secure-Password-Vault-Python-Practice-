import os
import json
import base64
import argparse
import getpass
import secrets
import sys # Added import for sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidTag


VAULT_FILENAME = "vault.enc"
META_FILENAME = "vault.meta"
SALT_SIZE = 16
PBKDF2_ITERATIONS = 200_000
KEY_SIZE = 32  # 256-bit
AAD = b"vault-v1"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return {
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
    }


def aesgcm_decrypt(key: bytes, enc: dict, associated_data: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(
        b64d(enc["nonce"]),
        b64d(enc["ciphertext"]),
        associated_data
    )


class SecureVault:
    def __init__(self, folder: Path):
        self.folder = folder

    def exists(self):
        return (
            self.folder.joinpath(VAULT_FILENAME).exists()
            and self.folder.joinpath(META_FILENAME).exists()
        )

    def init_vault(self, master_password: str):
        if self.exists():
            raise RuntimeError("Vault already exists")

        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key(master_password, salt)

        vault_struct = {
            "version": 1,
            "entries": {}
        }

        plaintext = json.dumps(vault_struct).encode("utf-8")
        enc = aesgcm_encrypt(key, plaintext, AAD)

        self.folder.mkdir(parents=True, exist_ok=True)
        self.folder.joinpath(VAULT_FILENAME).write_bytes(
            json.dumps(enc).encode("utf-8")
        )

        meta = {
            "salt": b64(salt),
            "kdf_iter": PBKDF2_ITERATIONS,
            "aad": "vault-v1"
        }

        self.folder.joinpath(META_FILENAME).write_text(
            json.dumps(meta)
        )

    def _load(self, master_password: str):
        meta = json.loads(self.folder.joinpath(META_FILENAME).read_text())
        salt = b64d(meta["salt"])
        key = derive_key(master_password, salt)

        enc = json.loads(self.folder.joinpath(VAULT_FILENAME).read_text())
        plaintext = aesgcm_decrypt(key, enc, AAD)
        return key, json.loads(plaintext.decode("utf-8"))

    def _save(self, key: bytes, vault: dict):
        plaintext = json.dumps(vault).encode("utf-8")
        enc = aesgcm_encrypt(key, plaintext, AAD)
        self.folder.joinpath(VAULT_FILENAME).write_text(json.dumps(enc))

    def add_entry(self, master_password: str, name: str, username: str, password: str, notes: str):
        key, vault = self._load(master_password)
        vault["entries"][name] = {
            "username": username,
            "password": password,
            "notes": notes
        }
        self._save(key, vault)

    def get_entry(self, master_password: str, name: str):
        _, vault = self._load(master_password)
        return vault["entries"].get(name)

    def list_entries(self, master_password: str):
        _, vault = self._load(master_password)
        return list(vault["entries"].keys())

    def delete_entry(self, master_password: str, name: str):
        key, vault = self._load(master_password)
        if name in vault["entries"]:
            del vault["entries"][name]
            self._save(key, vault)

    def change_master(self, old_pwd: str, new_pwd: str):
        _, vault = self._load(old_pwd)

        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key(new_pwd, salt)

        plaintext = json.dumps(vault).encode("utf-8")
        enc = aesgcm_encrypt(key, plaintext, AAD)

        self.folder.joinpath(VAULT_FILENAME).write_text(json.dumps(enc))
        self.folder.joinpath(META_FILENAME).write_text(json.dumps({
            "salt": b64(salt),
            "kdf_iter": PBKDF2_ITERATIONS,
            "aad": "vault-v1"
        }))


def main(argv=None): # Modified: added argv=None
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=[
        "init", "add", "get", "list", "delete", "change-master"
    ])
    parser.add_argument("--name")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--notes", default="")
    parser.add_argument("--vault", default=".vault")

    args = parser.parse_args(argv) # Modified: passed argv
    sv = SecureVault(Path(args.vault))

    try:
        if args.cmd == "init":
            pwd = getpass.getpass("Master password: ")
            sv.init_vault(pwd)

        elif args.cmd == "add":
            pwd = getpass.getpass("Master password: ")
            sv.add_entry(pwd, args.name, args.username, args.password, args.notes)

        elif args.cmd == "get":
            pwd = getpass.getpass("Master password: ")
            e = sv.get_entry(pwd, args.name)
            print(e)

        elif args.cmd == "list":
            pwd = getpass.getpass("Master password: ")
            for n in sv.list_entries(pwd):
                print("-", n)

        elif args.cmd == "delete":
            pwd = getpass.getpass("Master password: ")
            sv.delete_entry(pwd, args.name)

        elif args.cmd == "change-master":
            old = getpass.getpass("Old master password: ")
            new = getpass.getpass("New master password: ")
            sv.change_master(old, new)

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    # In a Colab notebook, sys.argv often contains the kernel's connection file
    # as the first argument, leading to argparse errors if not handled.
    # To prevent this error when the cell is run for definition,
    # we explicitly check for valid command-line arguments.
    
    # Check if there are actual command-line arguments that look like our commands.
    # If so, pass them to main. Otherwise, just load the code.
    if len(sys.argv) > 1 and sys.argv[1] in ["init", "add", "get", "list", "delete", "change-master"]:
        main(sys.argv[1:])
    else:
        print("Code loaded. To run a command, call main() with a list of arguments,")
        print("e.g., main(['init']) or main(['add', '--name', 'example', '--username', 'test_user', '--password', 'test_pass']).")
        print("The `getpass` function will prompt for the master password interactively.")