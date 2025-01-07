import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
import hashlib
import secrets
from redis import Redis
from porta_secura.config import settings
from Crypto.Cipher import AES


class SecurityManager:
    def __init__(self, redis_client: Redis):
        self.redis_client = redis_client
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM

    def create_token(self, wallet_address: str) -> str:
        expiration = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
        payload = {
            "sub": wallet_address,
            "exp": expiration,
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Dict:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

    def rate_limit_check(self, wallet_address: str) -> bool:
        key = f"rate_limit:{wallet_address}"
        current_count = self.redis_client.get(key)

        if not current_count:
            self.redis_client.setex(
                key,
                settings.RATE_LIMIT_PERIOD,
                1
            )
            return True

        if int(current_count) >= settings.RATE_LIMIT_REQUESTS:
            return False

        self.redis_client.incr(key)
        return True

    def generate_api_key(self, wallet_address: str) -> str:
        """Generate a secure API key for the wallet address."""
        random_bytes = secrets.token_bytes(32)
        timestamp = datetime.utcnow().timestamp()

        # Combine wallet address, random bytes, and timestamp
        combined = f"{wallet_address}:{random_bytes.hex()}:{timestamp}"

        # Create a hash of the combined string
        api_key = hashlib.sha256(combined.encode()).hexdigest()

        # Store the API key in Redis with the wallet address
        self.redis_client.hset("api_keys", api_key, wallet_address)

        return api_key

    def verify_api_key(self, api_key: str) -> Optional[str]:
        """Verify an API key and return the associated wallet address."""
        wallet_address = self.redis_client.hget("api_keys", api_key)
        if wallet_address:
            return wallet_address.decode()
        return None

    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        return bool(self.redis_client.hdel("api_keys", api_key))

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data before storing."""
        if not data:
            return data

        key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        nonce = secrets.token_bytes(12)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        # Combine nonce, ciphertext, and tag
        encrypted = nonce + ciphertext + tag
        return encrypted.hex()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        if not encrypted_data:
            return encrypted_data

        try:
            # Convert hex string back to bytes
            encrypted = bytes.fromhex(encrypted_data)

            # Extract components
            nonce = encrypted[:12]
            ciphertext = encrypted[12:-16]
            tag = encrypted[-16:]

            # Decrypt
            key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")