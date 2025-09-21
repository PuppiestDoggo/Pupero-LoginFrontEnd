from dotenv import load_dotenv
import os

def _to_bool(val: str, default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}

load_dotenv()

def _normalize(val: str | None, kind: str) -> str:
    # kind: 'backend','offers','transactions'
    defaults = {
        'backend': 'http://api-manager:8000/auth',
        'offers': 'http://api-manager:8000',
        'transactions': 'http://api-manager:8000/transactions',
    }
    if not val:
        return defaults[kind]
    v = val.strip().rstrip('/')
    if '://' in v:
        return v
    name = v
    if name in {'api-manager', 'pupero-api-manager'}:
        base = f'http://{name}:8000'
        return base + ('/auth' if kind == 'backend' else '/transactions' if kind == 'transactions' else '')
    if name in {'transactions', 'pupero-transactions'}:
        return f'http://{name}:8003'
    if name in {'offers', 'pupero-offers'}:
        return f'http://{name}:8002'
    return defaults[kind]

BACKEND_URL = _normalize(os.getenv('BACKEND_URL'), 'backend')
OFFERS_SERVICE_URL = _normalize(os.getenv('OFFERS_SERVICE_URL'), 'offers')
TRANSACTIONS_SERVICE_URL = _normalize(os.getenv('TRANSACTIONS_SERVICE_URL'), 'transactions')
SECRET_KEY = os.getenv('SECRET_KEY')
REMEMBER_ME_DAYS = int(os.getenv('REMEMBER_ME_DAYS', '30'))
SECURE_COOKIES = _to_bool(os.getenv('SECURE_COOKIES'), default=False)
SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
