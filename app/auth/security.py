
import hashlib
import secrets

from pwdlib import PasswordHash


_password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Return a secure password hash suitable for database storage."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")

    if len(password) > 1024:
        raise ValueError("Password is too long.")

    return _password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        return _password_hash.verify(password, stored_hash)
    except (ValueError, TypeError):
        return False


def generate_session_token() -> str:
    """Generate a cryptographically secure opaque session token."""
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Hash a session token before storing it in PostgreSQL."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def hash_csrf_token(token: str) -> str:
    """Hash a CSRF token before storing it in PostgreSQL."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()