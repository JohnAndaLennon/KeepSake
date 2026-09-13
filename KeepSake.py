#!/usr/bin/env python3
"""
Keepsake - A command-line password manager with TOTP recovery
Usage: keepsake [command] [vault_file] [args]

Security model for .totp companion file:
  - The TOTP secret and master password backup are bundled together and
    encrypted with a key derived from a separate seed phrase
  - The .totp file contains NO plaintext secrets. Opening it reveals only
    non-sensitive metadata (method, info) and an opaque encrypted blob.
  - Recovery requires BOTH the .totp file AND the seed phrase
    A valid live TOTP code is also checked as a second identity factor.
"""

import os
import sys
import subprocess
import json
import secrets
import getpass
import base64
import pyperclip
import pyotp
import string
import shutil
import io

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import date, timedelta, datetime
from mnemonic import Mnemonic

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

MIN_MASTER_PASSWORD_SCORE = 7
HEADER_MAGIC = b"KSAK\x01"
DEFAULT_VAULT = "default.vault"
VAULT_EXTENSION = ".vault"
MNEMONIC_STRENGTH = 128 #12 words
VAULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Vaults")

TOTP_MODES = ("every", "hourly", "daily", "recovery_only")
TOTP_MODE_LABELS = {
    "every": "Every password check",
    "hourly": "Once every hour",
    "daily": "Once every day",
    "recovery_only": "Only when recovering an account (default)",
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Generates secure password, self-explanatory
def generate_secure_password(num_length=20):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(secrets.choice(characters) for _ in range(num_length))

# Checks strength of password, 8 char, Aa + # + symbol
def check_password_strength(password):
    score = 0
    feedback = []
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if len(password) >= 8:              score += 1
    else: feedback.append("Password should be at least 8 characters long")

    if any(c.isupper() for c in password): score += 1
    else: feedback.append("Add uppercase letters")

    if any(c.islower() for c in password): score += 1
    else: feedback.append("Add lowercase letters")

    if any(c.isdigit() for c in password): score += 1
    else: feedback.append("Add numbers")

    if any(c in special_chars for c in password): score += 1
    else: feedback.append("Add special characters (!@#$%^&* etc.)")

    common = ['123', 'abc', 'password', 'qwerty', 'admin', 'root']
    if not any(p in password.lower() for p in common): score += 1
    else: feedback.append("Avoid common patterns like '123', 'password', etc.")

    if len(set(password)) > len(password) * 0.7: score += 1
    else: feedback.append("Avoid repeating characters")

    charset_size = 0
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(c in special_chars for c in password): charset_size += len(special_chars)

    if score >= 7:   strength = "Very Strong"
    elif score >= 6: strength = "Strong"
    elif score >= 5: strength = "Medium"
    elif score >= 4: strength = "Weak"
    else:            strength = "Very Weak"

    return {'score': score, 'strength': strength, 'feedback': feedback}

# Copies text to clipboard, removes from clipboard in 3 minutes
def copy_with_timer(text: str, seconds: int = 180):
    """Copy text to clipboard and spawn a detached process to clear it."""
    pyperclip.copy(text)

    # The detached cleaner script as a one-liner
    cleaner = (
        f"import time, pyperclip; "
        f"time.sleep({seconds}); "
        f"pyperclip.copy('')"
    )

    if sys.platform == "win32":
        # Windows: DETACHED_PROCESS flag severs the child from the parent
        subprocess.Popen(
            [sys.executable, "-c", cleaner],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            close_fds=True
        )
    else:
        # Unix/macOS: start_new_session=True detaches from the parent process group
        subprocess.Popen(
            [sys.executable, "-c", cleaner],
            start_new_session=True,
            close_fds=True
        )



# ─── Main Class ───────────────────────────────────────────────────────────────

class Keepsake:

    # ── Vault Encryption / Decryption ────────────────────────────────────────

    def _derive_key(self, password: str, salt:bytes) -> bytes:
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

    def _encrypt_file(self, data: dict, password:str) -> bytes:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(password,salt)
        ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode(),None)
        header = HEADER_MAGIC
        return header + salt + nonce + ciphertext

    def _decrypt_file(self, filename: str, password:str) -> dict:
        with open(filename, 'rb') as f:
            raw = f.read()

        if raw[:5] != HEADER_MAGIC:
            raise ValueError("Not a valid Keepsake Vault File.")
    
        salt       = raw[5:21]
        nonce      = raw[21:33]
        ciphertext = raw[33:]
        try:
            key = self._derive_key(password, salt)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())
        except Exception:
            raise ValueError(f"Decryption failed - incorrect password")

    def _save_file(self, filename: str, data: dict, password: str):
        encrypted = self._encrypt_file(data, password)
        tmp_path = filename + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(encrypted)
        os.replace(tmp_path, filename)

    def _load_file(self, filename: str, password: str) -> dict:
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"Vault file '{filename}' not found")
            return self._decrypt_file(filename, password)
        except FileNotFoundError:
            raise
        except Exception:
            raise ValueError("Failed to decrypt vault - incorrect password or corrupted file")

    def _check_expiry(self, entry: dict, program_name: str, username: str):
        """
        Check if a password entry is expired or approaching expiry.
        Prints a warning if within the reminder window or past the expiry date.
        Returns: 'expired', 'warning', or None
        """
        expires_on_str = entry.get("expires_on")
        if not expires_on_str:
            return None  # No timer set, nothing to check

        today        = date.today()
        expires_on   = date.fromisoformat(expires_on_str)
        remind_days  = entry.get("remind_days", 7)
        days_left    = (expires_on - today).days

        entry_type = entry.get("type", "password").upper()
        label = program_name if username == "_" else f"'{username}' @ '{program_name}'"

        if days_left < 0:
            print(f"\n  ⚠  WARNING: [{entry_type}] {label} EXPIRED "
                f"{abs(days_left)} day(s) ago ({expires_on_str}).")
            print(f"     Run: keepsake set <vault> to update it.\n")
            return "expired"
        elif days_left <= remind_days:
            print(f"\n  ⚠  REMINDER: [{entry_type}] {label} expires "
                f"in {days_left} day(s) on {expires_on_str}.")
            print(f"     Run: keepsake set <vault> to update it.\n")
            return "warning"

        return None

    # Grabs whatever field needs to be copied, then copies it to clipboard
    def _get_copyable_field(self, entry: dict) -> tuple[str, str]:
        """
        Returns (field_label, field_value) for the most sensitive field
        in an entry based on its type. Used by get() and find().
        """
        entry_type = entry.get("type", "password")
        if entry_type == "password":
            return "Password", entry.get("password", "")
        elif entry_type == "api":
            return "API Key", entry.get("key", "")
        elif entry_type == "ssh":
            return "Password", entry.get("password", "")
        elif entry_type == "database":
            # Prefer connection string if present, otherwise password
            return ("Connection String", entry["connection_string"]) \
                if entry.get("connection_string") \
                else ("Password", entry.get("password", ""))
        elif entry_type == "env":
            var = entry.get("var_name", "VAR")
            val = entry.get("value", "")
            return "Export line", f"export {var}={val}"
        elif entry_type == "note":
            return "Note", entry.get("content", "")
        return "Value", ""
    
    # ── TOTP Companion File ───────────────────────────────────────────────────

    def _totp_file(self, filename: str) -> str:
        return filename + ".totp"

    def _save_totp_companion(self, totp_file: str, secret: str, master_password: str, mnemonic_phrase: str):
        """
        Encrypt the TOTP secret and master password together using a key
        derived from a 12-word BIP39 recovery phrase. The resulting file
        contains NO plaintext secrets — only an opaque encrypted blob.

        The phrase itself carries 128 bits of entropy by construction, so
        no separate password-stretching KDF (Argon2) is needed here — the
        BIP39 seed derivation (PBKDF2-HMAC-SHA512, 2048 rounds) is sufficient
        given the high input entropy.

        Blob layout stored in 'recovery_data':
            base64( nonce[12] + aesgcm_ciphertext( json({secret, mp}) ) )
        """
        nonce = os.urandom(12)
        mnemo = Mnemonic("english")
        seed = mnemo.to_seed(mnemonic_phrase)
        key = seed[:32]  # AES-256-GCM key
        payload = json.dumps({"secret": secret, "mp": master_password}).encode()
        ciphertext = AESGCM(key).encrypt(nonce, payload, None)

        companion = {
            "recovery_data": base64.b64encode(nonce + ciphertext).decode()
        }
        tmp_path = totp_file + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(companion, f, indent=2)
        os.replace(tmp_path, totp_file)

    def _load_totp_companion(self, totp_file: str) -> dict:
        with open(totp_file, 'r') as f:
            return json.load(f)

    def _decrypt_recovery_data(self, companion: dict, mnemonic_phrase: str) -> dict:
        """
        Decrypt the recovery_data blob using the 12-word recovery phrase.
        Returns {'secret': ..., 'mp': ...} or raises ValueError on a bad phrase.
        """
        try:
            raw = base64.b64decode(companion["recovery_data"])
            nonce = raw[:12]
            ciphertext = raw[12:]
            mnemo = Mnemonic("english")
            seed = mnemo.to_seed(mnemonic_phrase)
            key = seed[:32]
            payload = AESGCM(key).decrypt(nonce, ciphertext, None)
            return json.loads(payload.decode())
        except (Exception):
            raise ValueError("Incorrect recovery phrase.")

    
    def _validate_mnemonic_input(self, phrase: str) -> bool:
        """Check word count and BIP39 checksum before attempting decryption."""
        mnemo = Mnemonic("english")
        words = phrase.strip().split()
        if len(words) != 12:
            print(f"Expected 12 words, got {len(words)}.")
            return False
        if not mnemo.check(phrase.strip()):
            print("Invalid recovery phrase — check word spelling and order.")
            return False
        return True

    def _generate_and_show_recovery_phrase(self) -> str:
        """Generate a new 12-word BIP39 recovery phrase, display it securely,
        and require the user to re-type it to confirm they wrote it down."""
        mnemo = Mnemonic("english")
        phrase = mnemo.generate(strength=MNEMONIC_STRENGTH)

        print("\nWrite down these 12 words IN ORDER on paper. This is your ONLY")
        print("way to recover your vault if you forget your master password.")
        print("Store it somewhere safe and offline — never as a screenshot,")
        print("never in cloud storage, never in this vault.\n")
        self._show_secret_secure(phrase, uri="Confirm you've written it down correctly.")
        return phrase

    def _prompt_recovery_phrase(self) -> str:
        """Prompt for an existing recovery phrase during recovery/testing."""
        while True:
            phrase = input("Enter your 12-word recovery phrase: ").strip()
            if self._validate_mnemonic_input(phrase):
                return phrase
            if input("Try again? (y/n): ").lower() != 'y':
                return phrase  # let it fail downstream with the generic error

    def _prompt_totp_mode(self) -> str:
        """Ask how often TOTP should be required for routine vault access."""
        print("\nHow often should Keepsake ask for a TOTP code?")
        for i, mode in enumerate(TOTP_MODES, 1):
            print(f"  {i}. {TOTP_MODE_LABELS[mode]}")
        while True:
            choice = input(f"Choose (1-{len(TOTP_MODES)}, default: 4): ").strip()
            if not choice:
                return "recovery_only"
            try:
                index = int(choice) - 1
                if 0 <= index < len(TOTP_MODES):
                    return TOTP_MODES[index]
            except ValueError:
                pass
            print("Invalid choice.")

    def _enforce_totp_policy(self, filename: str, data: dict, master_password: str) -> bool:
        """
        Check whether a live TOTP code is required right now, based on the
        vault's configured policy, and prompt for it if so. Returns True if
        the operation may proceed, False if the check failed or was aborted.

        Does nothing (returns True immediately) if TOTP was never set up,
        or if the policy mode is 'recovery_only'.
        """
        policy = data.get("totp_policy")
        secret = data.get("totp_secret")
        if not policy or not secret:
            return True  # TOTP not configured for routine checks

        mode = policy.get("mode", "recovery_only")
        if mode == "recovery_only":
            return True

        now = datetime.now()
        last_verified_str = policy.get("last_verified")
        due = True
        if last_verified_str:
            last_verified = datetime.fromisoformat(last_verified_str)
            elapsed = now - last_verified
            if mode == "hourly" and elapsed < timedelta(hours=1):
                due = False
            elif mode == "daily" and elapsed < timedelta(days=1):
                due = False
            # mode == "every" always leaves due = True

        if not due:
            return True

        totp = pyotp.TOTP(secret)
        code = input("Enter current TOTP code: ").strip()
        if not totp.verify(code, valid_window=1):
            print("Invalid TOTP code. Operation aborted.")
            return False

        policy["last_verified"] = now.isoformat()
        self._save_file(filename, data, master_password)
        return True
        
    def _show_secret_secure(self, secret: str, uri: str):
        print("\nTOTP secret is ready. It will display for ONE keypress, then clear.")
        print("Make sure no one is watching your screen.")
        input("Press Enter when ready...")

        qr_lines_printed = 0
        is_totp_uri = uri.startswith("otpauth://")

        if is_totp_uri and QRCODE_AVAILABLE:
            qr = qrcode.QRCode(border=1)
            qr.add_data(uri)
            qr.make(fit=True)
            buf = io.StringIO()
            qr.print_ascii(out=buf, invert=True)
            qr_output = buf.getvalue()
            print(f"\n{qr_output}")
            print("Scan the QR code above, or enter the details manually below:\n")
            qr_lines_printed = qr_output.count("\n") + 2  # +2 for the blank line and caption

        # Move cursor up and clear — works on any ANSI terminal (Linux/macOS/Windows 10+)
        print(f"\n  Secret : {secret}")
        print(f"  URI    : {uri}\n")

        input("Press Enter AFTER you've saved this to your authenticator app...")

        # Clear the lines we just printed (secret + URI + blank lines)
        cols = shutil.get_terminal_size((80, 24)).columns
        LINES_TO_CLEAR = 39
        print(f"\033[{LINES_TO_CLEAR}A", end="")   # move cursor up N lines
        for _ in range(LINES_TO_CLEAR):
            print(" " * cols)                       # overwrite with spaces
        print(f"\033[{LINES_TO_CLEAR}A", end="", flush=True)  # park cursor back up

        print("Secret cleared from terminal.")

    # ── Commands ─────────────────────────────────────────────────────────────

    def init(self, filename: str):
        """Initialize a new vault file."""
        if os.path.exists(filename):
            if input(f"'{filename}' already exists. Overwrite? (y/n): ").lower() != 'y':
                print("Aborted.")
                return

        print(f"Initializing vault: {filename}")
        while True:
            master_password = getpass.getpass("Create master password: ")
            if master_password != getpass.getpass("Confirm master password: "):
                print("Passwords do not match.")
                continue
            result = check_password_strength(master_password)
            if result['score'] < MIN_MASTER_PASSWORD_SCORE:
                print(f"Password too weak ({result['strength']}):")
                for fb in result['feedback']: print(f"  - {fb}")
                continue
            break

        vault_data = {"programs": {}}
        self._save_file(filename, vault_data, master_password)
        print(f"Vault '{filename}' created successfully!")

        if input("Set up TOTP recovery now? (y/n): ").lower() == 'y':
            self.setup_recovery(filename, master_password)

    def get(self, filename: str, program_name: str):
        """Retrieve stored credentials for a program."""
        try:
            password = getpass.getpass("Enter master password: ")
            data = self._load_file(filename, password)
            if not self._enforce_totp_policy(filename, data, password):
                return False

            if program_name not in data["programs"]:
                print(f"No entry found for '{program_name}'.")
                return False

            accounts = data["programs"][program_name]
            if not accounts:
                print(f"No accounts stored under '{program_name}'.")
                return False

            usernames = list(accounts.keys())
            if len(usernames) > 1:
                print(f"Multiple accounts for '{program_name}':")
                for i, u in enumerate(usernames, 1): print(f"  {i}. {u}")
                choice = input("Select account number: ").strip()
                try:
                    username = usernames[int(choice) - 1]
                except (ValueError, IndexError):
                    print("Invalid selection.")
                    return False
            else:
                username = usernames[0]

            entry = accounts[username]
            entry_type = entry.get("type", "password")

            print(f"\nProgram : {program_name}")
            if username != "_":
                print(f"Username: {username}")
            print(f"Type    : {entry_type.upper()}")

            # Print all non-sensitive fields
            if entry_type == "ssh":
                print(f"Host    : {entry.get('host', '')}:{entry.get('port', '22')}")
                if entry.get("key_path"):
                    print(f"Key file: {entry['key_path']}")
            elif entry_type == "database":
                print(f"Host    : {entry.get('host', '')}")
                if entry.get("port"):
                    print(f"Port    : {entry['port']}")
            elif entry_type == "api":
                print(f"Preview : {entry.get('prefix', '')}")
                if entry.get("endpoint"):
                    print(f"Endpoint: {entry['endpoint']}")
            elif entry_type == "env":
                print(f"Variable: {entry.get('var_name', '')}")

            # Copy the right field
            field_label, field_value = self._get_copyable_field(entry)
            try:
                CLIPBOARD_TIMEOUT = 180
                copy_with_timer(field_value, CLIPBOARD_TIMEOUT)
                minutes = CLIPBOARD_TIMEOUT // 60
                print(f"{field_label}: [copied to clipboard — clears in {minutes}m]")
            except Exception:
                print(f"(pyperclip unavailable - please confirm it's installed.)")

            self._check_expiry(accounts[username], program_name, username)
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False
    
    def _prompt_expiry(self, account_data: dict) -> dict:
        """Prompt for an optional expiry timer and return the updated entry dict."""
        if input("Set an expiry timer? (y/n): ").strip().lower() != 'y':
            return account_data
        while True:
            try:
                days_until = int(input("Days until expiry: ").strip())
                if days_until >= 1: break
                print("Must be at least 1 day.")
            except ValueError:
                print("Please enter a whole number.")
        while True:
            try:
                remind_days = int(input("Days before expiry to start reminding: ").strip())
                if remind_days < 0:
                    print("Must be 0 or more.")
                elif remind_days >= days_until:
                    print(f"Must be less than {days_until}.")
                else:
                    break
            except ValueError:
                print("Please enter a whole number.")
        account_data["expires_on"]  = (date.today() + timedelta(days=days_until)).isoformat()
        account_data["remind_days"] = remind_days
        print(f"Expires on: {account_data['expires_on']} (reminder {remind_days}d before)")
        return account_data

    def set_entry(self, filename: str, entry_type: str = None):
        """
        Authenticate once, then create or update an entry of the given type.
        If entry_type is None, the master password and TOTP gate are checked
        FIRST, and only then is the user asked to choose an entry type —
        a wrong master password never reveals the type picker.
        """
        try:
            master_password = getpass.getpass("Enter master password: ")
            data = self._load_file(filename, master_password)
        except FileNotFoundError as e:
            print(str(e))
            return False
        except ValueError as e:
            print("Incorrect master password." if "Decryption" in str(e) else str(e))
            return False

        if not self._enforce_totp_policy(filename, data, master_password):
            return False

        type_map = {
            "pass": self._set_pass_body,
            "api": self._set_api_body,
            "ssh": self._set_ssh_body,
            "database": self._set_database_body,
            "db": self._set_database_body,  # alias
            "env": self._set_env_body,
            "note": self._set_note_body,
        }

        if entry_type is None:
            print("Entry type: pass, api, ssh, database, env, note")
            entry_type = input("Choose type (default: pass): ").strip().lower() or "pass"

        handler = type_map.get(entry_type, self._set_pass_body)
        return handler(filename, data, master_password)

    def _set_pass_body(self, filename: str, data: dict, master_password: str):
        """Add or update credentials for a program."""
        try:
            program_name = input("Program name: ").strip()
            username = input("Username: ").strip()

            if input("Generate secure password? (y/n): ").lower() == 'y':
                password = generate_secure_password()
                pyperclip.copy(password)
                print(f"Generated password, copied to clipboard")
                
            else:
                while True:
                    password = getpass.getpass("Enter password: ")
                    if password != getpass.getpass("Confirm password: "):
                        print("Passwords do not match.")
                        continue
                    result = check_password_strength(password)
                    if result['score'] < 7:
                        print(f"Password Strength check ({result['strength']}):")
                        for fb in result['feedback']: print(f"  - {fb}")
                        if input("Are you sure you want to use this password? (y/n):").lower() == 'y':
                            break
                        else:
                            continue
                    if password == master_password:
                        print(f"Password cannot match Master password")
                        continue
                    break

            account_data = {"type": "password", "password": password}
            account_data = self._prompt_expiry(account_data)

            if program_name not in data["programs"]:
                data["programs"][program_name] = {}

            action = "updated" if username in data["programs"][program_name] else "added"
            data["programs"][program_name][username] = account_data

            self._save_file(filename, data, master_password)
            print(f"Account '{username}' for '{program_name}' {action} successfully!")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False
    
    def _set_api_body(self, filename: str, data: dict, master_password: str):
        """Add or update an API key entry."""
        try:
            service = input("Service name (e.g. OpenAI, GitHub): ").strip()
            key     = getpass.getpass("API Key: ")
            prefix  = key[:8] + "..." if len(key) > 8 else key  # preview only
            endpoint = input("Endpoint URL (optional, Enter to skip): ").strip()

            account_data = {"type": "api", "key": key, "prefix": prefix}
            if endpoint:
                account_data["endpoint"] = endpoint

            # Reuse expiry timer prompt
            account_data = self._prompt_expiry(account_data)

            data["programs"].setdefault(service, {})
            action = "updated" if "_" in data["programs"][service] else "added"
            data["programs"][service]["_"] = account_data

            self._save_file(filename, data, master_password)
            print(f"API key for '{service}' {action} successfully!")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False


    def _set_ssh_body(self, filename: str, data: dict, master_password: str):
        """Add or update an SSH credential entry."""
        try:
            host = input("Host / IP: ").strip()
            username = input("Username: ").strip()
            port     = input("Port (Enter for 22): ").strip() or "22"
            password = getpass.getpass("Password (Enter to skip if key-based): ")
            key_path = input("Key file path (Enter to skip): ").strip()

            account_data = {"type": "ssh", "host": host, "port": port}
            if password:
                account_data["password"] = password
            if key_path:
                account_data["key_path"] = key_path

            account_data = self._prompt_expiry(account_data)

            data["programs"].setdefault(host, {})
            action = "updated" if username in data["programs"][host] else "added"
            data["programs"][host][username] = account_data

            self._save_file(filename, data, master_password)
            print(f"SSH entry for '{username}@{host}' {action} successfully!")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False


    def _set_database_body(self, filename: str, data: dict, master_password: str):
        """Add or update a database credential entry."""
        try:
            name = input("Database name / label: ").strip()
            host     = input("Host (e.g. localhost): ").strip()
            port     = input("Port (Enter to skip): ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            conn_str = input("Connection string (optional, Enter to skip): ").strip()

            account_data = {"type": "database", "host": host,
                            "username": username, "password": password}
            if port:
                account_data["port"] = port
            if conn_str:
                account_data["connection_string"] = conn_str

            account_data = self._prompt_expiry(account_data)

            data["programs"].setdefault(name, {})
            action = "updated" if username in data["programs"][name] else "added"
            data["programs"][name][username] = account_data

            self._save_file(filename, data, master_password)
            print(f"Database entry '{name}' {action} successfully!")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False


    def _set_env_body(self, filename: str, data: dict, master_password: str):
        """Add or update an environment variable entry."""
        try:
            var_name = input("Variable name (e.g. OPENAI_API_KEY): ").strip().upper()
            value    = getpass.getpass("Value: ")

            account_data = {"type": "env", "var_name": var_name, "value": value}
            account_data = self._prompt_expiry(account_data)

            data["programs"].setdefault(var_name, {})
            action = "updated" if "_" in data["programs"][var_name] else "added"
            data["programs"][var_name]["_"] = account_data

            self._save_file(filename, data, master_password)
            print(f"Environment variable '{var_name}' {action} successfully!")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False


    def _set_note_body(self, filename: str, data: dict, master_password: str):
        """Add or update a freeform note (license key, serial, PIN, etc.)."""
        try:
            label = input("Note label (e.g. Windows License): ").strip()
            content = getpass.getpass("Content: ")

            account_data = {"type": "note", "content": content}

            data["programs"].setdefault(label, {})
            action = "updated" if "_" in data["programs"][label] else "added"
            data["programs"][label]["_"] = account_data

            self._save_file(filename, data, master_password)
            print(f"Note '{label}' {action} successfully!")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False

    def delete(self, filename: str, program_name: str):
        """Delete a program or a specific account under a program."""
        try:
            master_password = getpass.getpass("Enter master password: ")
            data = self._load_file(filename, master_password)
            if not self._enforce_totp_policy(filename, data, master_password):
                return False

            if program_name not in data["programs"]:
                print(f"No entry found for '{program_name}'.")
                return False

            accounts = data["programs"][program_name]
            keys = list(accounts.keys())

            # ── Build display list ────────────────────────────────────────────
            print(f"\nAccounts stored under '{program_name}':")
            for i, key in enumerate(keys, 1):
                entry = accounts[key]
                entry_type = entry.get("type", "password").upper()
                label = key if key != "_" else f"[{entry_type}]"
                print(f"  {i}. {label}")
            print(f"  all. Delete everything under '{program_name}'")
            print(f"  0. Cancel")

            choice = input("\nSelect entry to delete: ").strip().lower()

            # ── Handle cancel ─────────────────────────────────────────────────
            if choice == "0":
                print("Aborted.")
                return False

            # ── Handle delete all ─────────────────────────────────────────────
            elif choice == "all":
                if input(f"Delete ALL entries under '{program_name}'? (y/n): ").lower() != 'y':
                    print("Aborted.")
                    return False
                del data["programs"][program_name]
                print(f"All entries under '{program_name}' deleted.")

            # ── Handle numbered selection ─────────────────────────────────────
            else:
                try:
                    index = int(choice) - 1
                    if index < 0 or index >= len(keys):
                        print("Invalid selection.")
                        return False
                except ValueError:
                    print("Invalid input. Enter a number, 'all', or '0'.")
                    return False

                target_key = keys[index]
                entry = accounts[target_key]
                entry_type = entry.get("type", "password").upper()
                label = target_key if target_key != "_" else entry_type

                if input(f"Delete '{label}' from '{program_name}'? (y/n): ").lower() != 'y':
                    print("Aborted.")
                    return False

                del data["programs"][program_name][target_key]

                # Clean up the program block if it's now empty
                if not data["programs"][program_name]:
                    del data["programs"][program_name]
                    print(f"'{label}' deleted. '{program_name}' removed (no remaining entries).")
                else:
                    print(f"'{label}' deleted from '{program_name}'.")

            self._save_file(filename, data, master_password)
            return True

        except FileNotFoundError as e:
            print(str(e))
        except ValueError as e:
            print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False

    def list_programs(self, filename: str, type_filter: str = None):
        """List all stored programs and their accounts.

        If type_filter is given (e.g. "pass", "api", "ssh", "database",
        "env", "note"), only entries matching that type are shown. Left
        as None (default), every entry type is listed.
        """
        try:
            password = getpass.getpass("Enter master password: ")
            data = self._load_file(filename, password)
            if not self._enforce_totp_policy(filename, data, password):
                return False

            if not data["programs"]:
                print("No entries stored.")
                return True

            # "pass" is the CLI-facing name for the stored type "password"
            normalized_filter = "password" if type_filter == "pass" else type_filter

            header = "Stored programs:" if not normalized_filter else f"Stored programs [type: {type_filter}]:"
            print(f"\n{header}")

            any_shown = False
            for prog, accounts in sorted(data["programs"].items()):
                matching_accounts = {
                    uname: entry for uname, entry in accounts.items()
                    if not normalized_filter or entry.get("type", "password") == normalized_filter
                }
                if not matching_accounts:
                    continue

                any_shown = True
                print(f"  {prog}")
                for uname, entry in matching_accounts.items():
                    # Build status tag for the listing line
                    expires_on_str = entry.get("expires_on")
                    if expires_on_str:
                        today = date.today()
                        expires = date.fromisoformat(expires_on_str)
                        days_left = (expires - today).days
                        remind = entry.get("remind_days", 7)

                        if days_left < 0:
                            tag = f" [EXPIRED {abs(days_left)}d ago]"
                        elif days_left <= remind:
                            tag = f" [expires in {days_left}d]"
                        else:
                            tag = f" [expires {expires_on_str}]"
                    else:
                        tag = ""

                    entry_type = entry.get("type", "password").upper()
                    type_tag = f"[{entry_type}] " if entry_type != "PASSWORD" else ""
                    display = uname if uname != "_" else ""
                    print(f"    └─ {type_tag}{display}{tag}".rstrip())
                    # Full warning message if expired or in reminder window
                    self._check_expiry(entry, prog, uname)

            if not any_shown:
                label = type_filter if type_filter else "any type"
                print(f"No entries found matching type '{label}'.")
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False

    def reset_master_password(self, filename: str):
        """Reset the vault master password."""
        try:
            current_pw = getpass.getpass("Enter current master password: ")
            data = self._load_file(filename, current_pw)
            if not self._enforce_totp_policy(filename, data, current_pw):
                return False

            while True:
                new_pw = getpass.getpass("New master password: ")
                if new_pw != getpass.getpass("Confirm new master password: "):
                    print("Passwords do not match.")
                    continue
                result = check_password_strength(new_pw)
                if result['score'] < MIN_MASTER_PASSWORD_SCORE:
                    print(f"Password too weak ({result['strength']}):")
                    for fb in result['feedback']: print(f"  - {fb}")
                    continue
                break

            self._save_file(filename, data, new_pw)

            # Keep TOTP companion in sync if it exists
            totp_file = self._totp_file(filename)
            if os.path.exists(totp_file):
                print("\nTOTP recovery file detected. To keep it in sync,")
                print("enter your recovery phrase (or press Enter to skip — you")
                print("can re-run 'keepsake reset' later to update it).")
                mnemonic_phrase = input("Recovery phrase (Enter to skip): ").strip()
                if mnemonic_phrase:
                    try:
                        companion = self._load_totp_companion(totp_file)
                        payload = self._decrypt_recovery_data(companion, mnemonic_phrase)
                        self._save_totp_companion(
                            totp_file,
                            payload["secret"],
                            new_pw,
                            mnemonic_phrase
                        )
                        print("TOTP recovery file updated.")
                    except ValueError:
                        print("Incorrect recovery phrase — TOTP file NOT updated.")
                        print("Run 'keepsake reset' again with your NEW master password and the")
                        print("correct recovery phrase to sync the TOTP file.")
                else:
                    print("Skipped. TOTP recovery file still references the OLD master password.")
                    print("Run 'keepsake reset' again with your NEW master password and your")
                    print("recovery phrase to sync the TOTP ")

                print("\nMaster password reset successfully!")

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))

    def find(self, filename: str):
        """Search for a program by partial name, confirm matches interactively."""
        try:
            password = getpass.getpass("Enter master password: ")
            data = self._load_file(filename, password)
        except FileNotFoundError as e:
            print(str(e))
            return False
        except ValueError as e:
            print("Incorrect master password." if "Decryption" in str(e) else str(e))
            return False

        if not self._enforce_totp_policy(filename, data, password):
            return False

        if not data["programs"]:
            print("Vault is empty. Nothing to search.")
            return False

        query = input("Search for program: ").strip()
        if not query:
            print("No search term entered.")
            return False

        query_lower = query.lower()

        # Collect all programs whose lowercase name contains the query
        matches = [
            name for name in data["programs"]
            if query_lower in name.lower()
        ]

        if not matches:
            print(f"\nNo programs found matching '{query}'.")
            print(f"Tip: Run 'keepsake list {filename}' to see all stored programs.")
            return False

        print(f"\nFound {len(matches)} match(es). Confirming...\n")

        for name in matches:
            confirm = input(f"Did you mean '{name}'? (y/n): ").strip().lower()
            if confirm != 'y':
                continue

            # ── Confirmed: retrieve and display credentials ───────────────
            accounts = data["programs"][name]

            if not accounts:
                print(f"No accounts stored under '{name}'.")
                return False

            usernames = list(accounts.keys())

            if len(usernames) > 1:
                print(f"\nMultiple accounts for '{name}':")
                for i, u in enumerate(usernames, 1):
                    print(f"  {i}. {u}")
                choice = input("Select account number: ").strip()
                try:
                    username = usernames[int(choice) - 1]
                except (ValueError, IndexError):
                    print("Invalid selection.")
                    return False
            else:
                username = usernames[0]

            entry = accounts[username]
            field_label, field_value = self._get_copyable_field(entry)
            print(f"\nProgram : {name}")
            print(f"Username: {username}")
            try:
               CLIPBOARD_TIMEOUT = 180  # seconds — adjust to taste (180 = 3 min, 300 = 5 min)
               copy_with_timer(field_value, CLIPBOARD_TIMEOUT)
               minutes = CLIPBOARD_TIMEOUT // 60
               #timer_str = f"{minutes}m" if seconds == 0 else f"{minutes}m {seconds}s"
               print(f"{field_label}: [copied to clipboard — clears in {minutes}]")
            except Exception:
                print(f"(Clipboard unavailable. Install pyperclip to retrieve this entry.)")
            self._check_expiry(accounts[username], name, username)
            return True

        # ── All matches exhausted without a confirmation ──────────────────
        print(f"\nNo match confirmed for '{query}'.")
        print(f"Tip: Run 'keepsake list {filename}' to see all stored programs.")
        return False

    # ── TOTP Commands ─────────────────────────────────────────────────────────

    def setup_recovery(self, filename: str, master_password: str = None):
        """
        Set up TOTP-based recovery for a vault, and choose how often a live
        TOTP code should be required for routine vault access.

        The .totp file will contain:
        - method / info (plaintext metadata)
        - recovery_data (encrypted blob: secret + master password)

        The blob is encrypted with a key derived from your 12-word recovery
        phrase. Nothing sensitive is visible in plaintext.

        A copy of the TOTP secret is also stored inside the main vault
        (encrypted by the master password, same as everything else in the
        vault) so that routine checks only require the 6-digit code, not
        the recovery phrase.
        """
        try:
            if master_password is None:
                master_password = getpass.getpass("Enter master password: ")
            data = self._load_file(filename, master_password) # verify + reuse

            totp_file = self._totp_file(filename)
            if os.path.exists(totp_file):
                print("TOTP recovery already exists.")
                print("Use 'manual-auth' to complete authenticator setup if needed.")
                return False

            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name="Keepsake Recovery", issuer_name="Keepsake")

            print("\n=== TOTP Recovery Setup ===")
            print("\nAdd to your authenticator app:")
            print("  1. Open authenticator app → tap + → 'Enter a setup key'")
            print("  2. Account name: Keepsake Recovery")
            self._show_secret_secure(secret, uri)

            print("\nVerify your authenticator app is set up correctly.")
            code = input("Enter the current 6-digit code from the app: ").strip()
            if not totp.verify(code, valid_window=1):
                print("\nCode verification FAILED. TOTP setup cancelled.")
                print("Make sure you entered the secret key correctly in your app.")
                return False

            mode = self._prompt_totp_mode()

            print("\nNow generate your recovery phrase.")
            print("This 12-word phrase encrypts your TOTP secret and password backup.")
            print("It is separate from your master password.\n")
            mnemonic_phrase = self._generate_and_show_recovery_phrase()

            self._save_totp_companion(
                totp_file, secret,
                master_password, mnemonic_phrase
            )

            # Store a copy of the secret + chosen policy inside the vault itself,
            # so routine checks only need the 6-digit code, not the phrase.
            data["totp_secret"] = secret
            data["totp_policy"] = {"mode": mode, "last_verified": None}
            self._save_file(filename, data, master_password)

            print(f"\nTOTP recovery set up successfully!")
            print(f"Recovery file: {totp_file}")
            print(f"TOTP check frequency: {TOTP_MODE_LABELS[mode]}")
            print("\nYour .totp file now contains NO plaintext secrets.")
            print("Both the TOTP secret and password backup are encrypted")
            print("and can only be read with your 12-word recovery phrase.\n")
            print("⚠ Keep backups of:")
            print(f"  • {filename} (your encrypted vault)")
            print(f"  • {totp_file} (encrypted recovery data)")
            print("  • Your recovery phrase (written down, stored separately, offline)")
            print("\n⚠ IMPORTANT: We did not verify you wrote the phrase down correctly.")
            print(f"   Run 'keepsake totp-status --vault {filename}' now to confirm")
            print("   your recovery phrase and TOTP code both work before you need them.")

            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print("Incorrect master password." if "Decryption" in str(e) else str(e))
        return False

    def recover_password(self, filename: str):
        """
        Recover vault access when the master password is forgotten.
        Requires: the .totp file, the seed phrase, and a valid live TOTP code.
        """
        totp_file = self._totp_file(filename)
        if not os.path.exists(totp_file):
            print(f"No TOTP recovery file found for '{filename}'.")
            print(f"Expected: {totp_file}")
            print("Run 'keepsake setup-recovery <vault>' to enable TOTP recovery.")
            return False

        if not os.path.exists(filename):
            print(f"Vault file '{filename}' not found.")
            return False

        print("\n=== Keepsake TOTP Recovery ===")
        print("You will need your seed phrase and a TOTP code from your authenticator app.\n")

        try:
            companion = self._load_totp_companion(totp_file)
            mnemonic_phrase = self._prompt_recovery_phrase()
            payload = self._decrypt_recovery_data(companion, mnemonic_phrase)

            secret = payload["secret"]
            master_password = payload["mp"]

            # Second factor: verify live TOTP code
            totp = pyotp.TOTP(secret)
            code = input("Enter current TOTP code from your authenticator app: ").strip()
            if not totp.verify(code, valid_window=1):
                print("Invalid TOTP code. Recovery aborted.")
                return False

            print("\nIdentity verified! Master password recovered.")

            while True:
                new_pw = getpass.getpass("New master password: ")
                if new_pw != getpass.getpass("Confirm: "):
                    print("Passwords do not match.")
                    continue
                result = check_password_strength(new_pw)
                if result['score'] < MIN_MASTER_PASSWORD_SCORE:
                    print(f"Password too weak ({result['strength']}):")
                    for fb in result['feedback']: print(f"  - {fb}")
                    continue
                break

            data = self._load_file(filename, master_password)
            self._save_file(filename, data, new_pw)

            # Update companion with new master password (same seed phrase)
                    # Update companion with new master password (same recovery phrase)
            self._save_totp_companion(
                totp_file, secret,
                new_pw, mnemonic_phrase
            )
            print("Vault re-encrypted with new master password.")
            print("TOTP recovery file updated.")
            
            return True

        except FileNotFoundError as e: print(str(e))
        except ValueError as e: print(f"Recovery failed: {e}")
        return False

    def totp_status(self, filename: str):
        """Show TOTP recovery status and optionally test the authenticator app."""
        totp_file = self._totp_file(filename)
        if not os.path.exists(totp_file):
            print(f"TOTP recovery : NOT SET UP")
            print(f"Run: keepsake setup-recovery {filename}")
            return

        companion = self._load_totp_companion(totp_file)
        print(f"TOTP recovery : ENABLED")
        print(f"Recovery file : {totp_file}")
        print(f"Secret visible: NO (encrypted with seed phrase)")

        if input("\nTest authenticator app + recovery phrase? (y/n): ").lower() == 'y':
            try:
                mnemonic_phrase = self._prompt_recovery_phrase()
                payload = self._decrypt_recovery_data(companion, mnemonic_phrase)
                totp = pyotp.TOTP(payload["secret"])
                code = input("Enter current TOTP code: ").strip()
                if totp.verify(code, valid_window=1):
                    print("✓ Recovery phrase correct and TOTP code valid!")
                else:
                    print("✗ Recovery phrase correct but TOTP code invalid.")
                    print("  Check your authenticator app's time sync.")
            except ValueError as e:
                print(f"✗ {e}")

    def manual_add_to_authenticator(self, filename: str):
        """Display TOTP secret for re-adding to an authenticator app.
        Requires the seed phrase to decrypt the secret."""
        totp_file = self._totp_file(filename)
        if not os.path.exists(totp_file):
            print("No TOTP recovery set up. Run: keepsake setup-recovery <vault>")
            return False

        try:
            master_password = getpass.getpass("Enter master password: ")
            self._load_file(filename, master_password)

            print("Enter your recovery phrase to decrypt the TOTP secret.\n")
            mnemonic_phrase = self._prompt_recovery_phrase()
            companion = self._load_totp_companion(totp_file)
            payload = self._decrypt_recovery_data(companion, mnemonic_phrase)
            secret = payload["secret"]
            uri = pyotp.TOTP(secret).provisioning_uri(
                name="Keepsake Recovery", issuer_name="Keepsake"
            )

            print("\nTo add Keepsake Recovery to your authenticator app:")
            print("  1. Open authenticator app → tap + → 'Enter a setup key'")
            print("  2. Account name: Keepsake Recovery")
            self._show_secret_secure(secret, uri)
            return True

        except FileNotFoundError as e:
            print(str(e))
        except ValueError as e: 
            print("Incorrect master password." if "Decryption" in str(e) else f"Failed: {e}")
        return False


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

USAGE = """\
Keepsake - Command-line password manager

Usage: keepsake <command> [args] [--vault <file>]

If --vault/-v is omitted, the default vault "vault" (in the current
directory) is used automatically.

Vault commands:
  init                       Create a new vault
  get <program>              Copy a password to clipboard
  set [type]                 Add or update credentials, default type is pass
  delete <program>           Delete an entry or account interactively
  find                       Search for a program by partial name
  list [type]                List programs and accounts, optionally filtered by type
  reset                      Change the master password

set types:
  pass       Password: Program, Username, Password, Expiration (default)
  api        API Key: Service name, API Key, Expiration, URL
  ssh        SSH Credentials: Host/IP, Username, Port, Password, Key File
  database   Database Credentials: Name, Username, Password, Connection String
  env        Environment Variable
  note       Freeform note (license key, serial, PIN, etc.)

TOTP recovery commands:
  setup-recovery             Set up TOTP recovery (creates <vault>.totp)
  recover                    Recover access using recovery Phrase + TOTP code
  totp-status                Show TOTP recovery status
  manual-auth                Show TOTP secret for re-adding to authenticator

Examples:
  keepsake init                          Create default vault ("vault")
  keepsake init --vault work.vault       Create a named vault
  keepsake get github                    Get "github" from default vault
  keepsake get github -v work.vault      Get "github" from work.vault
  keepsake set pass                      Add a password entry to default vault
"""


def _extract_vault_arg(argv):
    """
    Pull --vault/-v <file> out of argv and return (vault_path, remaining_args).
    Falls back to DEFAULT_VAULT if no flag is present. Works regardless of
    where the flag appears in the argument list.
    """
    vault = DEFAULT_VAULT
    remaining = []
    i = 0
    while i < len(argv):
        if argv[i] in ("--vault", "-v"):
            if i + 1 >= len(argv):
                print("Error: --vault requires a filename argument.")
                sys.exit(1)
            vault = argv[i + 1]
            i += 2
        else:
            remaining.append(argv[i])
            i += 1
    return vault, remaining

def _normalize_vault_path(vault: str) -> str:
    """
    Ensure the vault filename ends in .vault, then resolve it inside the
    fixed Vaults/ directory next to this script. If the user passed an
    already-absolute path (or one containing a path separator), respect
    it as-is rather than forcing it into Vaults/ — this keeps the door
    open for advanced users who deliberately want a vault elsewhere.
    """
    if not vault.endswith(VAULT_EXTENSION):
        vault = vault + VAULT_EXTENSION

    if os.path.isabs(vault) or os.sep in vault or (os.altsep and os.altsep in vault):
        return vault

    os.makedirs(VAULTS_DIR, exist_ok=True)
    return os.path.join(VAULTS_DIR, vault)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(USAGE)
        return

    keepsake = Keepsake()
    command = sys.argv[1].lower()
    vault, args = _extract_vault_arg(sys.argv[2:])
    vault = _normalize_vault_path(vault)

    if command == "init":
        keepsake.init(vault)

    elif command == "get":
        if len(args) < 1:
            print("Usage: keepsake get <program> [--vault <file>]")
            sys.exit(1)
        keepsake.get(vault, args[0])

    elif command == "set":
        # Optional subcommand: keepsake set [type] [--vault <file>]
        sub = args[0].lower() if args else None
        valid_set_types = ("pass", "api", "ssh", "database", "db", "env", "note")
        if sub and sub not in valid_set_types:
            print(f"Unknown entry type '{sub}'. Valid types: pass, api, ssh, database, env, note")
            sys.exit(1)
        keepsake.set_entry(vault, sub)

    elif command == "delete":
        if len(args) < 1:
            print("Usage: keepsake delete <program> [--vault <file>]")
            sys.exit(1)
        keepsake.delete(vault, args[0])

    elif command == "list":
        valid_list_types = ("pass", "api", "ssh", "database", "db", "env", "note")
        type_filter = args[0].lower() if args else None
        if type_filter == "db":
            type_filter = "database"  # alias, matches set's alias behavior
        if type_filter and type_filter not in valid_list_types:
            print(f"Unknown entry type '{type_filter}'. Valid types: pass, api, ssh, database, env, note")
            sys.exit(1)
        keepsake.list_programs(vault, type_filter)

    elif command == "find":
        keepsake.find(vault)

    elif command == "reset":
        keepsake.reset_master_password(vault)

    elif command == "setup-recovery":
        keepsake.setup_recovery(vault)

    elif command == "recover":
        keepsake.recover_password(vault)

    elif command == "totp-status":
        keepsake.totp_status(vault)

    elif command == "manual-auth":
        keepsake.manual_add_to_authenticator(vault)

    else:
        print(f"Unknown command: '{command}'")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()