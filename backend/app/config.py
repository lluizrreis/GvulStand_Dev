import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    APP_NAME: str = "GvulStand - Vulnerability Management System"
    APP_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Security / Auth
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Initial Admin Credentials (as requested: Admin / Admin)
    DEFAULT_ADMIN_USERNAME: str = os.getenv("DEFAULT_ADMIN_USERNAME", "Admin")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin")
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@gvulstand.local")
    
    # Database
    # Supports SQLite (default local) or MariaDB/MySQL (mysql+pymysql://user:pass@host:3306/db)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        f"sqlite:///{DATA_DIR}/gvulstand.db"
    )
    
    # Storage
    UPLOAD_FOLDER: str = str(UPLOADS_DIR)
    
    # ISO 27000 / 9000 Defaults
    DEFAULT_SLA_CRITICAL_DAYS: int = 7
    DEFAULT_SLA_HIGH_DAYS: int = 15
    DEFAULT_SLA_MEDIUM_DAYS: int = 30
    DEFAULT_SLA_LOW_DAYS: int = 60

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"

settings = Settings()
