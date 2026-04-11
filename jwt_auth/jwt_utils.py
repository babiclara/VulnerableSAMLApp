from datetime import datetime, timezone, timedelta

import jwt

import config


def generate_access_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        'sub': user.id,
        'name': user.username,
        'role': user.role,
        'iat': now,
        'exp': now + timedelta(seconds=config.ACCESS_TOKEN_EXPIRY),
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def decode_access_token(token):
    return jwt.decode(token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM])