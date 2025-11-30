from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)  
    is_active = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False) 
    oauth_provider = db.Column(db.String(50), nullable=True)  
    oauth_id = db.Column(db.String(256), nullable=True)  
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_code = db.Column(db.String(6), nullable=True)  
    two_factor_code_expiry = db.Column(db.DateTime, nullable=True)  
    totp_secret = db.Column(db.String(64), nullable=True)  
    failed_login_count = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime, nullable=True)

    MAX_FAILED = 3

    def is_locked(self):
        if self.lock_until is None:
            return False
        return datetime.datetime.utcnow() < self.lock_until

    def reset_failed(self):
        self.failed_login_count = 0
        self.lock_until = None

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='login_attempts')
