from getpass import getpass
from sqlalchemy import select
from app.db.database import SessionLocal
from app.models.user import User, UserRole

email = input("Enter the registered email to promote: ").strip().lower()

with SessionLocal() as db:
    existing_admin = db.scalar(
        select(User).where(User.role == UserRole.SUPER_ADMIN)
    )

    if existing_admin:
        print("A Super Admin already exists. No changes made.")
    else:
        user = db.scalar(select(User).where(User.email == email))
        if not user:
            print("User not found. Register the user first.")
        else:
            user.role = UserRole.SUPER_ADMIN
            user.is_active = True
            db.commit()
            print(f"{email} is now the Super Admin.")
