"""
JWT Token Security Extension: Refresh Token Persistence & Blacklisting
======================================================================
Secure Coding Assignment — Algebra Bernays University 2025/2026

This file contains the complete implementation:
  - RefreshToken model/entity (§3.1)
  - Repository layer with query methods (§3.2)
  - RefreshTokenService with full lifecycle (§3.3)
  - REST API endpoints (§3.4)
  - Security configuration (§3.5)
  - Scheduled cleanup (§3.3.4)

Run:
    pip install -r requirements.txt
    python app.py
"""

import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt as pyjwt
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash

# ─── Configuration (from environment — NOT hardcoded, §4) ─────────────
# All secrets and expiry values come from environment variables.
# Defaults are provided ONLY for local development.

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///refresh_tokens.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'flask-secret-change-me')

# IMPORTANT: access and refresh token use DIFFERENT secrets (§4 Don'ts)
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'access-secret-change-me')
JWT_REFRESH_SECRET_KEY = os.environ.get('JWT_REFRESH_SECRET_KEY', 'refresh-secret-change-me')

# Expiry from configuration, NOT hardcoded (§4 Dos)
ACCESS_TOKEN_EXPIRY = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRY_SECONDS', '900'))       # 15 min
REFRESH_TOKEN_EXPIRY = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRY_SECONDS', '604800'))  # 7 days
CLEANUP_INTERVAL = int(os.environ.get('CLEANUP_INTERVAL_SECONDS', '3600'))                # 1 hour

JWT_ALGORITHM = 'HS512'

# ─── Logging ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

# ─── Database ──────────────────────────────────────────────────────────
db = SQLAlchemy(app)


# ══════════════════════════════════════════════════════════════════════
# §3.1 — DATABASE MODELS (Entity Layer)
# ══════════════════════════════════════════════════════════════════════

class User(db.Model):
    """User entity. Passwords are hashed — never stored as plaintext."""
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='USER')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    refresh_tokens = db.relationship('RefreshToken', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class RefreshToken(db.Model):
    """
    RefreshToken entity — stores each issued refresh token in the database.

    Fields (per §3.1):
      id               — UUID primary key, auto-generated
      token            — unique, cryptographically random string (UUID v4)
      expiry_date      — absolute expiry timestamp
      revoked          — blacklist flag (default False)
      user_id          — FK to User (@ManyToOne)
      created_at       — audit: when the token was issued
      replaced_by_token — rotation tracking for reuse detection (optional)
    """
    __tablename__ = 'refresh_tokens'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token = db.Column(db.String(256), unique=True, nullable=False, index=True)
    expiry_date = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    replaced_by_token = db.Column(db.String(256), nullable=True)

    @property
    def is_expired(self):
        now = datetime.now(timezone.utc)
        expiry = self.expiry_date
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now > expiry


# ══════════════════════════════════════════════════════════════════════
# §3.2 — REPOSITORY LAYER (Query Methods)
# ══════════════════════════════════════════════════════════════════════

def find_by_token(token_value):
    """Find any token (including revoked) by value. Required for reuse detection."""
    return RefreshToken.query.filter_by(token=token_value).first()


def find_by_token_and_not_revoked(token_value):
    """Find a valid, non-revoked token. Used during refresh flow."""
    return RefreshToken.query.filter_by(token=token_value, revoked=False).first()


def revoke_all_by_user_id(user_id):
    """Mark ALL tokens for a user as revoked. Used on logout & breach."""
    count = RefreshToken.query.filter_by(user_id=user_id, revoked=False).update({'revoked': True})
    db.session.commit()
    logger.info("Revoked %d token(s) for user_id=%s", count, user_id)
    return count


def delete_expired_before(cutoff):
    """Delete tokens past their expiry_date. Called by scheduled cleanup."""
    count = RefreshToken.query.filter(RefreshToken.expiry_date < cutoff).delete()
    db.session.commit()
    logger.info("Cleaned up %d expired token(s)", count)
    return count


# ══════════════════════════════════════════════════════════════════════
# §3.3 — SERVICE LAYER (RefreshTokenService)
# ══════════════════════════════════════════════════════════════════════

class TokenReuseDetected(Exception):
    """Raised when a revoked token is reused — indicates theft."""
    pass

class TokenInvalid(Exception):
    """Raised when the token is not found in the DB."""
    pass

class TokenExpired(Exception):
    """Raised when the token exists but has expired."""
    pass


# §3.3.1 — Token Creation
def create_refresh_token(user_id):
    """Generate a cryptographically secure token, persist to DB, return it."""
    token_value = str(uuid.uuid4())
    expiry_date = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRY)

    rt = RefreshToken(
        token=token_value,
        expiry_date=expiry_date,
        revoked=False,
        user_id=user_id,
    )
    db.session.add(rt)
    db.session.commit()

    logger.info("SECURITY — Refresh token CREATED for user_id=%s, expires=%s", user_id, expiry_date)
    return rt


# §3.3.2 — Token Verification & Refresh Flow (with rotation + reuse detection)
def verify_and_rotate(token_value):
    """
    1. Look up token in DB.
    2. If found but REVOKED → REUSE ATTACK → revoke ALL user tokens → exception.
    3. If not found → exception.
    4. If expired → revoke it → exception.
    5. If valid → revoke old (rotation), create new, return (user_id, new_token).
    """
    existing = find_by_token(token_value)

    if existing is None:
        logger.warning("SECURITY — Refresh with UNKNOWN token")
        raise TokenInvalid("Refresh token not found.")

    if existing.revoked:
        logger.critical("SECURITY — TOKEN REUSE DETECTED for user_id=%s! Revoking ALL.", existing.user_id)
        revoke_all_by_user_id(existing.user_id)
        raise TokenReuseDetected("Refresh token reuse detected. All sessions revoked.")

    if existing.is_expired:
        existing.revoked = True
        db.session.commit()
        logger.warning("SECURITY — Expired token used by user_id=%s", existing.user_id)
        raise TokenExpired("Refresh token has expired.")

    # Rotation: revoke old, create new
    existing.revoked = True
    new_token = create_refresh_token(existing.user_id)
    existing.replaced_by_token = new_token.token
    db.session.commit()

    logger.info("SECURITY — Token ROTATED for user_id=%s", existing.user_id)
    return existing.user_id, new_token


# §3.3.3 — Token Revocation (Blacklisting)
def revoke_all_user_tokens(user_id):
    """Logout: revoke all refresh tokens for the user."""
    count = revoke_all_by_user_id(user_id)
    logger.info("SECURITY — LOGOUT: revoked %d token(s) for user_id=%s", count, user_id)
    return count


# §3.3.4 — Scheduled Cleanup
def cleanup_expired_tokens():
    """Delete expired tokens. Revoked-but-not-expired are kept for audit."""
    now = datetime.now(timezone.utc)
    count = delete_expired_before(now)
    logger.info("SCHEDULED CLEANUP — removed %d expired token(s)", count)
    return count


# ══════════════════════════════════════════════════════════════════════
# JWT ACCESS TOKEN UTILITIES
# ══════════════════════════════════════════════════════════════════════

def generate_access_token(user):
    """Create a signed JWT. Payload has NO sensitive PII (§4 Don'ts)."""
    now = datetime.now(timezone.utc)
    payload = {
        'sub': user.id,
        'name': user.username,
        'role': user.role,
        'iat': now,
        'exp': now + timedelta(seconds=ACCESS_TOKEN_EXPIRY),
    }
    return pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token):
    """Validate and decode a JWT access token."""
    return pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])


# ══════════════════════════════════════════════════════════════════════
# §3.5 — SECURITY CONFIGURATION (Auth Decorators — stateless, no sessions)
# ══════════════════════════════════════════════════════════════════════

def auth_required(f):
    """Require valid Bearer access token. Stateless — no HTTP sessions."""
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
    """Require ADMIN role + valid access token."""
    @wraps(f)
    @auth_required
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'ADMIN':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════════
# §3.4 — REST ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

# POST /api/auth/login — Public (permitAll)
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user. Return access token + refresh token. Persist to DB."""
    data = request.get_json(silent=True)
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user is None or not user.check_password(data['password']):
        logger.warning("SECURITY — Failed login for username=%s", data.get('username'))
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = generate_access_token(user)
    refresh_token = create_refresh_token(user.id)

    logger.info("SECURITY — LOGIN success for user=%s", user.username)
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token.token,
        'token_type': 'Bearer',
    }), 200


# POST /api/auth/refresh — Public (refresh token in request body, §3.5)
@app.route('/api/auth/refresh', methods=['POST'])
def refresh():
    """Validate refresh token from DB. Rotate: revoke old, issue new pair."""
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

    logger.info("SECURITY — Token REFRESHED for user=%s", user.username)
    return jsonify({
        'access_token': access_token,
        'refresh_token': new_rt.token,
        'token_type': 'Bearer',
    }), 200


# POST /api/auth/logout — Requires Bearer access token (§3.5)
@app.route('/api/auth/logout', methods=['POST'])
@auth_required
def logout():
    """Revoke (blacklist) all refresh tokens for the authenticated user. Returns 204."""
    revoke_all_user_tokens(g.current_user['sub'])
    logger.info("SECURITY — LOGOUT for user=%s", g.current_user['name'])
    return '', 204


# POST /api/auth/revoke — ADMIN only (bonus endpoint)
@app.route('/api/auth/revoke', methods=['POST'])
@admin_required
def revoke():
    """Admin: revoke all tokens for a specific user by user_id."""
    data = request.get_json(silent=True)
    if not data or 'user_id' not in data:
        return jsonify({'error': 'user_id required'}), 400
    target = User.query.get(data['user_id'])
    if not target:
        return jsonify({'error': 'User not found'}), 404
    count = revoke_all_user_tokens(target.id)
    return jsonify({'message': f'Revoked {count} token(s) for user {target.username}'}), 200


# Sample protected endpoint — to prove auth works
@app.route('/api/protected', methods=['GET'])
@auth_required
def protected():
    return jsonify({'message': 'Access granted', 'user': g.current_user}), 200


# ══════════════════════════════════════════════════════════════════════
# STARTUP — Create tables, seed users, start scheduler
# ══════════════════════════════════════════════════════════════════════

def seed_users():
    """Create test users if they don't exist."""
    users = [
        ('yogi', 'bear', 'USER'),
        ('admin', 'adminpassword', 'ADMIN'),
        ('brubble', 'password', 'USER'),
    ]
    for username, password, role in users:
        if not User.query.filter_by(username=username).first():
            u = User(username=username, role=role)
            u.set_password(password)
            db.session.add(u)
            logger.info("Seeded user: %s (%s)", username, role)
    db.session.commit()


with app.app_context():
    db.create_all()
    seed_users()

# §3.3.4 — Scheduled cleanup using APScheduler
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    lambda: app.app_context().push() or cleanup_expired_tokens(),
    trigger='interval',
    seconds=CLEANUP_INTERVAL,
    id='cleanup_expired_tokens',
)
scheduler.start()

if __name__ == '__main__':
    logger.info("Starting JWT Auth server on http://127.0.0.1:5000")
    logger.info("Endpoints:")
    logger.info("  POST /api/auth/login     — public")
    logger.info("  POST /api/auth/refresh   — public")
    logger.info("  POST /api/auth/logout    — requires Bearer token")
    logger.info("  POST /api/auth/revoke    — requires ADMIN")
    logger.info("  GET  /api/protected      — requires Bearer token")
    app.run(host='127.0.0.1', port=5000, debug=False)