from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models import db, User, LoginAttempt

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/logs')
@login_required
def logs():
    if not current_user.is_admin:
        flash('Доступ заборонено. Тільки адміністратори можуть переглядати логи.', 'danger')
        return redirect(url_for('index'))
    
    query = LoginAttempt.query
    
    # Filter by status
    status_filter = request.args.get('status', 'all')
    if status_filter == 'success':
        query = query.filter_by(success=True)
    elif status_filter == 'failed':
        query = query.filter_by(success=False)
    
    # Filter by username
    username_filter = request.args.get('username', '').strip()
    if username_filter:
        user = User.query.filter_by(username=username_filter).first()
        if user:
            query = query.filter_by(user_id=user.id)
        else:
            query = query.filter_by(user_id=-1)
    
    attempts = query.order_by(LoginAttempt.timestamp.desc()).limit(200).all()
    return render_template('logs.html', attempts=attempts)


@admin_bp.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Доступ заборонено. Тільки адміністратори можуть переглядати користувачів.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin_users.html', users=users)


@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Доступ заборонено.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Ви не можете видалити свій власний акаунт через адмін-панель.', 'warning')
        return redirect(url_for('admin.users'))
    
    username = user.username
    try:
        LoginAttempt.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        flash(f'Користувача "{username}" успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Помилка при видаленні користувача.', 'danger')
        print(f'Error deleting user: {e}')
    
    return redirect(url_for('admin.users'))
