import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-in-prod")
    DEBUG = True
    HIBP_TIMEOUT = 5
    HIBP_USER_AGENT = "password-analyzer-local/1.0"
    MAX_PASSWORD_LENGTH = 128