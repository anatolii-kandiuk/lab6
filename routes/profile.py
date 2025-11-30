from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from models import db, LoginAttempt
from forms import TwoFactorForm, ChangePasswordForm

profile_bp = Blueprint('profile', __name__)
bcrypt = Bcrypt()


@profile_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = TwoFactorForm()
    password_form = ChangePasswordForm()
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable':
            current_user.two_factor_enabled = True
            db.session.commit()
            flash('2FA увімкнено. При наступному вході ви отримаєте код на пошту.', 'success')
            return redirect(url_for('profile.profile'))
        elif action == 'disable':
            current_user.two_factor_enabled = False
            current_user.two_factor_code = None
            current_user.two_factor_code_expiry = None
            current_user.totp_secret = None
            db.session.commit()
            flash('2FA вимкнено.', 'info')
            return redirect(url_for('profile.profile'))
    
    return render_template('profile.html', form=form, password_form=password_form)



@profile_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not bcrypt.check_password_hash(current_user.password_hash, form.old_password.data):
            flash('Поточний пароль невірний.', 'danger')
            return redirect(url_for('profile.profile'))
        
        current_user.password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        db.session.commit()
        flash('Пароль успішно змінено!', 'success')
        return redirect(url_for('profile.profile'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{error}', 'danger')
        return redirect(url_for('profile.profile'))


@profile_bp.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    confirm = request.form.get('confirm', '').lower()
    if confirm != 'видалити':
        flash('Ви не підтвердили видалення. Введіть "видалити".', 'warning')
        return redirect(url_for('profile.profile'))

    username = current_user.username
    user_id = current_user.id

    try:
        LoginAttempt.query.filter_by(user_id=user_id).delete()
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash(f'Акаунт користувача "{username}" успішно видалено.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash('Помилка при видаленні акаунту. Спробуйте пізніше.', 'danger')
        print(f'Error deleting account: {e}')
        return redirect(url_for('profile.profile'))
