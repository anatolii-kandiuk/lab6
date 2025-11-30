import os
import datetime
import random
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from models import db, User, LoginAttempt
from forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, TwoFactorForm
from email_utils import send_email

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY', 'dev-secret-key-change-me'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if 'captcha' not in session:
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        session['captcha'] = {'q': f'{a} + {b} = ?', 'ans': str(a + b)}
    captcha = session.get('captcha')

    if form.validate_on_submit():
        if form.captcha.data.strip() != session.get('captcha', {}).get('ans'):
            flash('Невірна CAPTCHA. Спробуйте ще раз.', 'danger')
            session.pop('captcha', None)
            return redirect(url_for('auth.register'))

        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed, is_active=False)
        db.session.add(user)
        db.session.commit()

        # Send activation email
        token = serializer.dumps(user.email, salt='email-activate')
        link = url_for('auth.activate_account', token=token, _external=True)
        send_email(user.email, 'Activate your account', f'Click to activate: {link}')
        flash('Реєстрація успішна! Перевірте пошту для активації. Токен дійсний протягом 1 години.', 'success')
        session.pop('captcha', None)
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form, captcha=captcha)


@auth_bp.route('/activate/<token>')
def activate_account(token):
    try:
        email = serializer.loads(token, salt='email-activate', max_age=3600)
    except Exception:
        flash('Неправильний або прострочений токен активації.', 'danger')
        return redirect(url_for('auth.register'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Користувача не знайдено.', 'warning')
        return redirect(url_for('auth.register'))
    
    user.is_active = True
    db.session.commit()
    flash('Акаунт активовано, можете увійти.', 'success')
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        ip = request.remote_addr
        
        if not user:
            flash('Користувача не знайдено. Будь ласка, зареєструйтесь.', 'warning')
            return redirect(url_for('auth.register'))

        # Check lockout
        if user.is_locked():
            remaining_time = user.lock_until - datetime.datetime.utcnow()
            minutes = int(remaining_time.total_seconds() / 60) + 1
            flash(f'Акаунт тимчасово заблоковано через надто багато невдалих спроб. Спробуйте через {minutes} хв.', 'danger')
            return redirect(url_for('auth.login'))

        if not user.is_active:
            flash('Акаунт не активовано. Перевірте пошту.', 'warning')
            return redirect(url_for('auth.login'))

        if bcrypt.check_password_hash(user.password_hash, form.password.data):
            # If 2FA enabled, send code via email
            if user.two_factor_enabled:
                code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                user.two_factor_code = code
                user.two_factor_code_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
                db.session.commit()
                
                send_email(user.email, 'Код двофакторної автентифікації', 
                          f'Ваш код для входу: {code}\n\nКод дійсний протягом 10 хвилин.\n\nЯкщо це не ви, проігноруйте цей лист.')
                
                session['pre_2fa_userid'] = user.id
                attempt = LoginAttempt(user_id=user.id, ip_address=ip, success=False)
                db.session.add(attempt)
                db.session.commit()
                flash('Код двофакторної автентифікації відправлено на вашу пошту.', 'info')
                return redirect(url_for('auth.two_factor'))

            # Successful login
            login_user(user)
            attempt = LoginAttempt(user_id=user.id, ip_address=ip, success=True)
            user.reset_failed()
            db.session.add(attempt)
            db.session.commit()
            flash('Успішний вхід.', 'success')
            return redirect(url_for('index'))
        else:
            # Wrong password
            attempt = LoginAttempt(user_id=user.id, ip_address=ip, success=False)
            user.failed_login_count += 1
            remaining_attempts = User.MAX_FAILED - user.failed_login_count
            
            if user.failed_login_count >= User.MAX_FAILED:
                user.lock_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
                db.session.add(attempt)
                db.session.commit()
                flash('Акаунт заблоковано на 15 хвилин через перевищення кількості спроб входу.', 'danger')
            else:
                db.session.add(attempt)
                db.session.commit()
                flash(f'Невірний логін або пароль. Залишилось спроб: {remaining_attempts}', 'danger')
            
            return redirect(url_for('auth.login'))

    return render_template('login.html', form=form)


@auth_bp.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_userid' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['pre_2fa_userid'])
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        # Check if code is expired
        if user.two_factor_code_expiry and datetime.datetime.utcnow() > user.two_factor_code_expiry:
            flash('Код прострочений. Спробуйте увійти знову.', 'danger')
            session.pop('pre_2fa_userid', None)
            return redirect(url_for('auth.login'))
        
        # Verify code
        if user.two_factor_code and form.token.data.strip() == user.two_factor_code:
            user.two_factor_code = None
            user.two_factor_code_expiry = None
            login_user(user)
            attempt = LoginAttempt(user_id=user.id, ip_address=request.remote_addr, success=True)
            user.reset_failed()
            db.session.add(attempt)
            db.session.commit()
            session.pop('pre_2fa_userid', None)
            flash('2FA успішна. Ви увійшли.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Невірний код 2FA', 'danger')
    
    return render_template('two_factor.html', form=form)


@auth_bp.route('/logout')
def logout():
    logout_user()
    flash('Ви вийшли.', 'info')
    return redirect(url_for('index'))


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset')
            link = url_for('auth.reset_token', token=token, _external=True)
            send_email(user.email, 'Password reset', f'Reset link: {link}')
        flash('Якщо такий email зареєстровано, на нього буде відправлено лист для скидання пароля. Токен дійсний протягом 1 години.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('reset_request.html', form=form)


@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash('Неправильний або прострочений токен.', 'danger')
        return redirect(url_for('auth.reset_request'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Користувача не знайдено.', 'warning')
        return redirect(url_for('auth.register'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash('Пароль оновлено, можете увійти.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_token.html', form=form)
