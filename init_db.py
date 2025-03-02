from flask_sqlalchemy import SQLAlchemy
from app import app, db

def init_database():
    with app.app_context():
        db.drop_all()
        # Create all tables with the updated schema
        db.create_all()
        print("Database 'healthqr.db' and tables created successfully.")

if __name__ == "__main__":
    init_database()