import uuid
import logging
from datetime import datetime, timezone, timedelta

from database import db
from models import RefreshToken
import repository
import config

logger = logging.getLogger(__name__)


class TokenReuseDetected(Exception):
    pass

class TokenInvalid(Exception):
    pass

class TokenExpired(Exception):
    pass


def create_refresh_token(user_id):
    token_value = str(uuid.uuid4())
    expiry_date = datetime.now(timezone.utc) + timedelta(seconds=config.REFRESH_TOKEN_EXPIRY)

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


def verify_and_rotate(token_value):
    existing = repository.find_by_token(token_value)

    if existing is None:
        logger.warning("SECURITY — Refresh with UNKNOWN token")
        raise TokenInvalid("Refresh token not found.")

    if existing.revoked:
        logger.critical("SECURITY — TOKEN REUSE DETECTED for user_id=%s! Revoking ALL.", existing.user_id)
        repository.revoke_all_by_user_id(existing.user_id)
        raise TokenReuseDetected("Refresh token reuse detected. All sessions revoked.")

    if existing.is_expired:
        existing.revoked = True
        db.session.commit()
        logger.warning("SECURITY — Expired token used by user_id=%s", existing.user_id)
        raise TokenExpired("Refresh token has expired.")

    existing.revoked = True
    new_token = create_refresh_token(existing.user_id)
    existing.replaced_by_token = new_token.token
    db.session.commit()

    logger.info("SECURITY — Token ROTATED for user_id=%s", existing.user_id)
    return existing.user_id, new_token


def revoke_all_user_tokens(user_id):
    count = repository.revoke_all_by_user_id(user_id)
    logger.info("SECURITY — LOGOUT: revoked %d token(s) for user_id=%s", count, user_id)
    return count


def cleanup_expired_tokens():
    now = datetime.now(timezone.utc)
    count = repository.delete_expired_before(now)
    logger.info("SCHEDULED CLEANUP — removed %d expired token(s)", count)
    return count