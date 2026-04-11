from functools import wraps

from flask import request, jsonify, g

from jwt_utils import decode_access_token


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        try:
            payload = decode_access_token(auth_header[7:])
        except Exception:
            return jsonify({'error': 'Invalid or expired access token'}), 401
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @auth_required
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'ADMIN':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated