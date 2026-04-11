
import logging

from flask import Flask, jsonify, g
from apscheduler.schedulers.background import BackgroundScheduler

import config
from database import db
from models import User, RefreshToken
from controller import auth_bp
from security import auth_required
from service import cleanup_expired_tokens

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = config.SECRET_KEY

db.init_app(app)

app.register_blueprint(auth_bp)

@app.route('/api/protected', methods=['GET'])
@auth_required
def protected():
    return jsonify({'message': 'Access granted', 'user': g.current_user}), 200


def seed_users():
    users = [
        ('lara', 'babic', 'USER'),
        ('admin', 'admin123', 'ADMIN'),
        ('loris', 'babic', 'USER'),
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

scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    lambda: app.app_context().push() or cleanup_expired_tokens(),
    trigger='interval',
    seconds=config.CLEANUP_INTERVAL,
    id='cleanup_expired_tokens',
)
scheduler.start()

if __name__ == '__main__':
    logger.info("Server starting on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)
