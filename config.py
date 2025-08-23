from dotenv import load_dotenv
import os

def _to_bool(val: str, default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}

load_dotenv()

BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:8000')
OFFERS_SERVICE_URL = os.getenv('OFFERS_SERVICE_URL', 'http://localhost:8001')
SECRET_KEY = os.getenv('SECRET_KEY')
REMEMBER_ME_DAYS = int(os.getenv('REMEMBER_ME_DAYS', '30'))
SECURE_COOKIES = _to_bool(os.getenv('SECURE_COOKIES'), default=False)
SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
