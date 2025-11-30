from app import create_app
from models import db, User
from flask_bcrypt import Bcrypt

def create_default_admin():
    app = create_app()
    bcrypt = Bcrypt(app)
    
    with app.app_context():
        existing = User.query.filter_by(email='anatolii.kandiuk.19@pnu.edu.ua').first()
        if existing:
            if not existing.is_admin:
                existing.is_admin = True
                db.session.commit()
                print(f"✓ Користувачу '{existing.username}' надано права адміністратора")
            else:
                print(f"✓ Адміністратор '{existing.username}' вже існує")
            return
        
        hashed = bcrypt.generate_password_hash('Admin_2025').decode('utf-8')
        admin = User(
            username='Адмін',
            email='anatolii.kandiuk.19@pnu.edu.ua',
            password_hash=hashed,
            is_active=True, 
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        
        print(f"  Ім'я: Адмін")
        print(f"  Email: anatolii.kandiuk.19@pnu.edu.ua")
        print(f"  Password: Admin_2025")

if __name__ == '__main__':
    create_default_admin()
