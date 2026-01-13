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
        'backend': 'http://pupero-api-manager:8000/auth',
        'offers': 'http://pupero-api-manager:8000',
        'transactions': 'http://pupero-api-manager:8000/transactions',
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

# Matrix chat integration (frontend)
MATRIX_ENABLED = _to_bool(os.getenv('MATRIX_ENABLED', '1'), default=True)
# Backend URL (as seen from the Flask container) to call Synapse Client API
MATRIX_HS_URL_BACKEND = os.getenv('MATRIX_HS_URL_BACKEND', 'http://host.docker.internal:8008').rstrip('/')
# Element Web URL (as seen from the user's browser) for embedding
MATRIX_ELEMENT_URL = os.getenv('MATRIX_ELEMENT_URL', '/element').rstrip('/')
# The homeserver name used by Synapse (MXIDs are @user:SERVER_NAME)
MATRIX_SERVER_NAME = os.getenv('MATRIX_SERVER_NAME', 'localhost')
# Local username prefix for mapping Pupero user IDs to Matrix usernames
MATRIX_USER_PREFIX = os.getenv('MATRIX_USER_PREFIX', 'u')
# Secret used to derive deterministic Matrix passwords for Pupero users
MATRIX_DEFAULT_PASSWORD_SECRET = os.getenv('MATRIX_DEFAULT_PASSWORD_SECRET', 'change-me')
# Number of days after which to archive trade chat rooms (0 = disabled)
MATRIX_TRADE_CHANNEL_ARCHIVE_DAYS = int(os.getenv('MATRIX_TRADE_CHANNEL_ARCHIVE_DAYS', '7'))
