import os

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///refresh_tokens.db')

SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'flask-secret-change-me')

JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'access-secret-change-me')
JWT_REFRESH_SECRET_KEY = os.environ.get('JWT_REFRESH_SECRET_KEY', 'refresh-secret-change-me')

ACCESS_TOKEN_EXPIRY = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRY_SECONDS', '900'))
REFRESH_TOKEN_EXPIRY = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRY_SECONDS', '604800'))
CLEANUP_INTERVAL = int(os.environ.get('CLEANUP_INTERVAL_SECONDS', '3600'))

JWT_ALGORITHM = 'HS512'