from app import app, db

# Create an application context
with app.app_context():
    # Now you can perform operations that require the application context
    db.drop_all()
    db.create_all()
