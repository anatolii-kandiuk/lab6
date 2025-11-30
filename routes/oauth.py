import os
from flask import Blueprint, redirect, url_for, flash, request
from flask_login import login_user
from authlib.integrations.flask_client import OAuth
from models import db, User, LoginAttempt

oauth_bp = Blueprint('oauth', __name__)

# OAuth will be initialized in the factory
oauth = None
google = None


def init_oauth(app):
    global oauth, google
    oauth = OAuth(app)
    google = oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )


@oauth_bp.route('/login/google')
def google_login():
    redirect_uri = url_for('oauth.google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@oauth_bp.route('/authorize/google')
def google_authorize():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            flash('Не вдалося отримати інформацію від Google.', 'danger')
            return redirect(url_for('auth.login'))
        
        email = user_info.get('email')
        name = user_info.get('name', email.split('@')[0])
        google_id = user_info.get('sub')
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if needed
            if not user.oauth_provider:
                user.oauth_provider = 'google'
                user.oauth_id = google_id
                user.is_active = True
                db.session.commit()
        else:
            # Create new user
            user = User(
                username=name,
                email=email,
                password_hash=None,
                oauth_provider='google',
                oauth_id=google_id,
                is_active=True
            )
            db.session.add(user)
            db.session.commit()
        
        # Log in the user
        login_user(user)
        attempt = LoginAttempt(user_id=user.id, ip_address=request.remote_addr, success=True)
        db.session.add(attempt)
        db.session.commit()
        
        flash(f'Вхід виконано через Google як {user.username}', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f'OAuth error: {e}')
        flash('Помилка авторизації через Google. Спробуйте ще раз.', 'danger')
        return redirect(url_for('auth.login'))
