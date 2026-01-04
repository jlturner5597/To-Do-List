"""
Cryptographic Utilities
Provides encryption/decryption for sensitive data at rest
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_encryption_key():
    """
    Get or derive the encryption key from environment variable.
    Uses PBKDF2 to derive a proper Fernet key from the secret.
    """
    secret = os.environ.get('ENCRYPTION_KEY', os.environ.get('SECRET_KEY', 'default-dev-key'))
    
    # Use a fixed salt (in production, this could be stored separately)
    # The salt is not secret, just needs to be consistent
    salt = b'todo-app-token-encryption-salt-v1'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
    return key


def get_fernet():
    """Get Fernet instance for encryption/decryption."""
    return Fernet(get_encryption_key())


def encrypt_value(value):
    """
    Encrypt a string value.
    Returns base64-encoded encrypted string.
    """
    if not value:
        return value
    
    f = get_fernet()
    encrypted = f.encrypt(value.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_value(encrypted_value):
    """
    Decrypt an encrypted string value.
    Returns the original plaintext string.
    """
    if not encrypted_value:
        return encrypted_value
    
    try:
        f = get_fernet()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception:
        # If decryption fails (e.g., data was stored unencrypted before),
        # return the value as-is for backwards compatibility
        return encrypted_value


def encrypt_token_data(token_data):
    """
    Encrypt sensitive fields in token data.
    Encrypts: access_token, refresh_token, client_secret
    """
    if not token_data:
        return token_data
    
    encrypted = token_data.copy()
    
    # Fields to encrypt
    sensitive_fields = ['access_token', 'refresh_token', 'client_secret']
    
    for field in sensitive_fields:
        if encrypted.get(field):
            encrypted[field] = encrypt_value(encrypted[field])
    
    return encrypted


def decrypt_token_data(encrypted_data):
    """
    Decrypt sensitive fields in token data.
    Decrypts: access_token, refresh_token, client_secret
    """
    if not encrypted_data:
        return encrypted_data
    
    decrypted = encrypted_data.copy()
    
    # Fields to decrypt
    sensitive_fields = ['access_token', 'refresh_token', 'client_secret']
    
    for field in sensitive_fields:
        if decrypted.get(field):
            decrypted[field] = decrypt_value(decrypted[field])
    
    return decrypted
