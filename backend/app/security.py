"""Password hashing, session tokens and encryption of stored secrets."""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

log = logging.getLogger(__name__)
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    secret = settings.app_secret_key.strip()
    if not secret:
        key_file = settings.data_path / ".secret_key"
        if key_file.exists():
            secret = key_file.read_text().strip()
        else:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            secret = secrets.token_hex(32)
            key_file.write_text(secret)
            try:
                key_file.chmod(0o600)
            except OSError:
                pass
            log.info("Generated application secret key at %s", key_file)
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode() if value else ""


def decrypt_secret(value: str | None) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        log.error("Could not decrypt a stored secret (APP_SECRET_KEY changed?). Re-enter it in Settings.")
        return ""
