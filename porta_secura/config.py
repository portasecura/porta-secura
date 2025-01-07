from pydantic import BaseSettings
from typing import Dict, List, Optional


class Settings(BaseSettings):
    APP_NAME: str = "PortaSecura"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # API Settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 4

    # Security Settings
    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 30

    # Solana Blockchain Settings
    SOLANA_NETWORK: str = "mainnet-beta"
    PORTA_TOKEN_ADDRESS: str
    MINIMUM_BALANCE: float = 1.0

    # Filter Settings
    DEFAULT_SENSITIVITY: float = 0.7
    FILTER_CATEGORIES: List[str] = [
        "personal_info",
        "credentials",
        "adult_content",
        "api_keys",
        "financial_data"
    ]

    # Cache Settings
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL: int = 3600

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 60

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()