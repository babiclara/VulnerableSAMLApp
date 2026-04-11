import logging

from database import db
from models import RefreshToken

logger = logging.getLogger(__name__)


def find_by_token(token_value):
    return RefreshToken.query.filter_by(token=token_value).first()


def find_by_token_and_not_revoked(token_value):
    return RefreshToken.query.filter_by(token=token_value, revoked=False).first()


def revoke_all_by_user_id(user_id):
    count = RefreshToken.query.filter_by(user_id=user_id, revoked=False).update({'revoked': True})
    db.session.commit()
    logger.info("Revoked %d token(s) for user_id=%s", count, user_id)
    return count


def delete_expired_before(cutoff):
    count = RefreshToken.query.filter(RefreshToken.expiry_date < cutoff).delete()
    db.session.commit()
    logger.info("Cleaned up %d expired token(s)", count)
    return count