"""Routes package"""
from .auth import auth_bp
from .profile import profile_bp
from .admin import admin_bp
from .oauth import oauth_bp, init_oauth

__all__ = ['auth_bp', 'profile_bp', 'admin_bp', 'oauth_bp', 'init_oauth']
