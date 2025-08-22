from dotenv import load_dotenv
import os

load_dotenv()

BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:8000')
SECRET_KEY = os.getenv('SECRET_KEY')
REMEMBER_ME_DAYS = int(os.getenv('REMEMBER_ME_DAYS', '30'))
