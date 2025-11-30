from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User
import re

class RegistrationForm(FlaskForm):
    username = StringField("Ім'я користувача", validators=[DataRequired(), Length(min=2, max=64)])
    email = StringField('Електронна пошта', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Підтвердження пароля', validators=[DataRequired(), EqualTo('password')])
    captcha = StringField('CAPTCHA', validators=[DataRequired()])
    submit = SubmitField('Зареєструватися')

    def validate_password(self, field):
        pw = field.data
        if len(pw) < 8:
            raise ValidationError('Пароль має бути не менше 8 символів')
        if not re.search(r'[A-Z]', pw):
            raise ValidationError('Пароль повинен містити велику літеру')
        if not re.search(r'[a-z]', pw):
            raise ValidationError('Пароль повинен містити малу літеру')
        if not re.search(r'\d', pw):
            raise ValidationError('Пароль повинен містити цифру')
        if not re.search(r'[^A-Za-z0-9]', pw):
            raise ValidationError('Пароль повинен містити спеціальний символ')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Ім\'я користувача вже використовується')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email вже використовується')

class LoginForm(FlaskForm):
    email = StringField('Електронна пошта', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запам\'ятати мене')
    submit = SubmitField('Увійти')

class RequestResetForm(FlaskForm):
    email = StringField('Електронна пошта', validators=[DataRequired(), Email()])
    submit = SubmitField('Надіслати посилання для скидання пароля')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Новий пароль', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Підтвердження пароля', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Скинути пароль')

    def validate_password(self, field):
        pw = field.data
        if len(pw) < 8:
            raise ValidationError('Пароль має бути не менше 8 символів')
        if not re.search(r'[A-Z]', pw):
            raise ValidationError('Пароль повинен містити велику літеру')
        if not re.search(r'[a-z]', pw):
            raise ValidationError('Пароль повинен містити малу літеру')
        if not re.search(r'\d', pw):
            raise ValidationError('Пароль повинен містити цифру')
        if not re.search(r'[^A-Za-z0-9]', pw):
            raise ValidationError('Пароль повинен містити спеціальний символ')

class TwoFactorForm(FlaskForm):
    token = StringField('Код 2FA', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Підтвердити')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Поточний пароль', validators=[DataRequired()])
    new_password = PasswordField('Новий пароль', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Підтвердження нового пароля', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Змінити пароль')

    def validate_new_password(self, field):
        pw = field.data
        if len(pw) < 8:
            raise ValidationError('Пароль має бути не менше 8 символів')
        if not re.search(r'[A-Z]', pw):
            raise ValidationError('Пароль повинен містити велику літеру')
        if not re.search(r'[a-z]', pw):
            raise ValidationError('Пароль повинен містити малу літеру')
        if not re.search(r'\d', pw):
            raise ValidationError('Пароль повинен містити цифру')
        if not re.search(r'[^A-Za-z0-9]', pw):
            raise ValidationError('Пароль повинен містити спеціальний символ')
