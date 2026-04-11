import logging

from flask import Blueprint, request, jsonify, g

from models import User
from jwt_utils import generate_access_token
from security import auth_required, admin_required
from service import (
    create_refresh_token,
    verify_and_rotate,
    revoke_all_user_tokens,
    TokenReuseDetected,
    TokenInvalid,
    TokenExpired,
)

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user is None or not user.check_password(data['password']):
        logger.warning("SECURITY — failed login for user", data.get('username'))
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = generate_access_token(user)
    refresh_token = create_refresh_token(user.id)

    logger.info("SECURITY — LOGIN success for user", user.username)
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token.token,
        'token_type': 'Bearer',
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json(silent=True)
    if not data or 'refresh_token' not in data:
        return jsonify({'error': 'refresh_token required in body'}), 400

    try:
        user_id, new_rt = verify_and_rotate(data['refresh_token'])
    except TokenReuseDetected as e:
        return jsonify({'error': str(e)}), 401
    except TokenInvalid as e:
        return jsonify({'error': str(e)}), 401
    except TokenExpired as e:
        return jsonify({'error': str(e)}), 401

    user = User.query.get(user_id)
    access_token = generate_access_token(user)

    return jsonify({
        'access_token': access_token,
        'refresh_token': new_rt.token,
        'token_type': 'Bearer',
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@auth_required
def logout():
    revoke_all_user_tokens(g.current_user['sub'])
    logger.info("SECURITY — LOGOUT for user=%s", g.current_user['name'])
    return '', 204


@auth_bp.route('/revoke', methods=['POST'])
@admin_required
def revoke():
    data = request.get_json(silent=True)
    if not data or 'user_id' not in data:
        return jsonify({'error': 'user_id required'}), 400

    target = User.query.get(data['user_id'])
    if not target:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'message': f'Revoked token for user'}), 200