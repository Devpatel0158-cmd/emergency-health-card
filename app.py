from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import qrcode
import os
import base64
from io import BytesIO
import json
import logging
from werkzeug.utils import secure_filename

# Initialize Flask app - the core of our web application
app = Flask(__name__)
# Using an environment variable for the secret key, with a fallback for development
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'f8754ee9be88b3f0575e1e1b1a2271c9943f0948e94674ad')

# Set up SQLite database - chose SQLite for simplicity during development
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthqr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disabled to suppress a warning

# File upload configuration - needed for profile pictures
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Keeping uploads in a static folder for easy access
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit, might adjust later if needed

# Make sure the upload folder exists - had an issue where it failed without this
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize extensions
bcrypt = Bcrypt(app)  # For password hashing - security first!
db = SQLAlchemy(app)  # ORM for database management
login_manager = LoginManager(app)  # Handling user sessions
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

# Logging setup - added this after debugging some weird errors
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database Models
# UserAuth model for authentication - decided to add username later for flexibility
class UserAuth(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)  # Added this after initial design
    password = db.Column(db.String(120), nullable=False)

# HealthCard model - the core of the app, stores all health info
class HealthCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_auth.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    date_of_birth = db.Column(db.String(10))
    height = db.Column(db.Float)
    weight = db.Column(db.Float)
    blood_type = db.Column(db.String(3), nullable=False)
    allergies = db.Column(db.Text)
    medications = db.Column(db.Text)
    emergency_contact = db.Column(db.String(15))
    emergency_contacts = db.Column(db.Text)  # JSON string for multiple contacts
    health_conditions = db.Column(db.Text)
    notes = db.Column(db.Text)
    profile_picture = db.Column(db.String(100))
    qr_code = db.Column(db.Text)
    # New fields from template
    gender = db.Column(db.String(20))
    address = db.Column(db.Text)
    contact_number = db.Column(db.String(15))
    eye_color = db.Column(db.String(50))
    hair_color = db.Column(db.String(50))
    past_surgeries = db.Column(db.Text)
    chronic_illnesses = db.Column(db.Text)
    family_medical_history = db.Column(db.Text)
    immunization_history = db.Column(db.Text)
    hospitalization_history = db.Column(db.Text)
    smoking_status = db.Column(db.String(20))
    alcohol_consumption = db.Column(db.String(100))
    drug_use = db.Column(db.String(100))
    exercise_routine = db.Column(db.String(100))
    diet_preferences = db.Column(db.String(100))
    primary_care_physician = db.Column(db.String(200))
    insurance_info = db.Column(db.String(200))
    blood_pressure = db.Column(db.String(20))
    heart_rate = db.Column(db.Integer)
    oxygen_saturation = db.Column(db.Integer)

# User loader for Flask-Login - took me a bit to figure out this was needed
@login_manager.user_loader
def load_user(user_id):
    return UserAuth.query.get(int(user_id))

# Helper function for saving profile pics - had to tweak this to avoid filename conflicts
def save_profile_picture(file, user_id):
    if file:
        filename = secure_filename(file.filename)  # Security measure for filenames
        # Using user_id to make filenames unique - ran into overwrite issues before this
        unique_filename = f"{user_id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return unique_filename
    return None

# Routes
# Login route - decided to allow login with either email or username
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['email']  # Using 'email' field for both, keeps frontend simple
        password = request.form['password']
        # Querying with OR condition - took a while to get this syntax right
        user = UserAuth.query.filter((UserAuth.email == identifier) | (UserAuth.username == identifier)).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login Successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid email/username or password', 'danger')
    return render_template('login.html')

# Signup route - added username field after initial version
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']  # Added this to make logins more user-friendly
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if UserAuth.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
        elif UserAuth.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            new_user = UserAuth(email=email, username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

# Forgot password - placeholder for now, might implement email reset later
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        flash('Password reset instructions sent to your email (simulated).', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

# Logout - simple but essential
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Index route - dashboard if logged in, landing page if not
@app.route('/')
def index():
    if current_user.is_authenticated:
        health_cards = HealthCard.query.filter_by(user_id=current_user.id).all()
        # Simplifying data for the template - didn’t want to pass full objects
        health_cards_data = [{'id': card.id, 'name': card.name, 'blood_type': card.blood_type} for card in health_cards]
        return render_template('dashboard.html', health_cards=health_cards_data, user_username=current_user.username)
    return render_template('landing.html')

# Create health card - the meat of the app, took a while to get QR and uploads working
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_health_card():
    if request.method == 'POST':
        try:
            name = request.form['name']
            age = request.form['age']
            date_of_birth = request.form.get('date_of_birth', '')  # Optional field
            height = float(request.form['height']) if request.form.get('height') else None
            weight = float(request.form['weight']) if request.form.get('weight') else None
            blood_type = request.form['blood_type']
            allergies = request.form.get('allergies', '')
            medications = request.form.get('medications', '')
            # Handling multiple emergency contacts - this was tricky to figure out
            emergency_numbers = request.form.getlist('emergency_contact_number[]')
            emergency_relations = request.form.getlist('emergency_contact_relation[]')
            emergency_contacts = [
                {"number": emergency_numbers[i], "relation": emergency_relations[i] if i < len(emergency_relations) else ""}
                for i in range(len(emergency_numbers)) if emergency_numbers[i]
            ]
            emergency_contacts_json = json.dumps(emergency_contacts)
            emergency_contact = emergency_numbers[0] if emergency_numbers else ""
            health_conditions = request.form.get('health_conditions', '')
            notes = request.form.get('notes', '')

            # Profile picture upload - had to debug file handling here
            profile_picture = request.files.get('profile_picture')
            profile_picture_filename = save_profile_picture(profile_picture, current_user.id) if profile_picture else None

            # QR code generation - chose base64 to embed directly in HTML
            qr_url = f"https://yourusername.pythonanywhere.com/user/{current_user.id}"  # Placeholder URL for now
            qr = qrcode.make(qr_url)
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

            # Saving the card - had some commit issues before adding try/except
            new_card = HealthCard(
                user_id=current_user.id, name=name, age=age, date_of_birth=date_of_birth,
                height=height, weight=weight, blood_type=blood_type, allergies=allergies,
                medications=medications, emergency_contact=emergency_contact,
                emergency_contacts=emergency_contacts_json, health_conditions=health_conditions,
                notes=notes, profile_picture=profile_picture_filename, qr_code=qr_base64
            )
            db.session.add(new_card)
            db.session.commit()

            return render_template('qr.html', qr_base64=qr_base64, user_id=new_card.id)
        except Exception as e:
            logger.error(f"Error in create_health_card: {str(e)}", exc_info=True)
            flash('An error occurred while generating the QR code or uploading the profile picture.', 'danger')
            return redirect(url_for('index'))
    return render_template('index.html')

# Edit health card - reused a lot from create, but added permission checks
@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_health_card(user_id):
    card = HealthCard.query.get_or_404(user_id)
    if card.user_id != current_user.id:
        flash('You do not have permission to edit this card.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            # Update all fields from the form
            card.name = request.form['name']
            card.age = int(request.form['age'])
            card.date_of_birth = request.form.get('date_of_birth', '')
            card.height = float(request.form['height']) if request.form.get('height') else None
            card.weight = float(request.form['weight']) if request.form.get('weight') else None
            card.blood_type = request.form['blood_type']
            card.allergies = request.form.get('allergies', '')
            card.medications = request.form.get('medications', '')
            # Handle emergency contacts with name field
            emergency_numbers = request.form.getlist('emergency_contact_number[]')
            emergency_relations = request.form.getlist('emergency_contact_relation[]')
            emergency_names = request.form.getlist('emergency_contact_name[]')
            emergency_contacts = [
                {
                    "number": emergency_numbers[i],
                    "relation": emergency_relations[i] if i < len(emergency_relations) else "",
                    "name": emergency_names[i] if i < len(emergency_names) else ""
                }
                for i in range(len(emergency_numbers)) if emergency_numbers[i]
            ]
            card.emergency_contacts = json.dumps(emergency_contacts)
            card.emergency_contact = emergency_numbers[0] if emergency_numbers else ""
            card.health_conditions = request.form.get('health_conditions', '')
            card.notes = request.form.get('notes', '')
            # New fields
            card.gender = request.form['gender']
            card.address = request.form.get('address', '')
            card.contact_number = request.form.get('contact_number', '')
            card.eye_color = request.form.get('eye_color', '')
            card.hair_color = request.form.get('hair_color', '')
            card.past_surgeries = request.form.get('past_surgeries', '')
            card.chronic_illnesses = request.form.get('chronic_illnesses', '')
            card.family_medical_history = request.form.get('family_medical_history', '')
            card.immunization_history = request.form.get('immunization_history', '')
            card.hospitalization_history = request.form.get('hospitalization_history', '')
            card.smoking_status = request.form.get('smoking_status', '')
            card.alcohol_consumption = request.form.get('alcohol_consumption', '')
            card.drug_use = request.form.get('drug_use', '')
            card.exercise_routine = request.form.get('exercise_routine', '')
            card.diet_preferences = request.form.get('diet_preferences', '')
            card.primary_care_physician = request.form.get('primary_care_physician', '')
            card.insurance_info = request.form.get('insurance_info', '')
            card.blood_pressure = request.form.get('blood_pressure', '')
            card.heart_rate = int(request.form['heart_rate']) if request.form.get('heart_rate') else None
            card.oxygen_saturation = int(request.form['oxygen_saturation']) if request.form.get('oxygen_saturation') else None

            # Profile picture update
            profile_picture = request.files.get('profile_picture')
            if profile_picture:
                profile_picture_filename = save_profile_picture(profile_picture, current_user.id)
                card.profile_picture = profile_picture_filename

            # Regenerate QR code - use card.id as before, but ensure it’s always fresh
            qr_url = f"https://yourusername.pythonanywhere.com/user/{card.id}"
            qr = qrcode.make(qr_url)
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            card.qr_code = qr_base64

            db.session.commit()
            flash('Health card updated successfully!', 'success')
            return render_template('qr.html', qr_base64=qr_base64, user_id=card.id)
        except ValueError as ve:
            logger.error(f"ValueError in edit_health_card: {str(ve)}", exc_info=True)
            flash('Invalid input data (e.g., numbers). Please check your entries.', 'danger')
            return redirect(url_for('edit_health_card', user_id=user_id))
        except Exception as e:
            logger.error(f"Error in edit_health_card: {str(e)}", exc_info=True)
            flash(f'An error occurred: {str(e)}. Please try again.', 'danger')
            return redirect(url_for('edit_health_card', user_id=user_id))
    return render_template('edit_health_card.html', user=card)

# Public route to view user data via QR scan - no auth required for accessibility
@app.route('/user/<int:user_id>')
def get_user_data(user_id):
    card = HealthCard.query.get_or_404(user_id)
    user_data = {
        'id': card.id, 'name': card.name, 'age': card.age, 'date_of_birth': card.date_of_birth,
        'height': card.height, 'weight': card.weight, 'blood_type': card.blood_type,
        'allergies': card.allergies, 'medications': card.medications, 'emergency_contact': card.emergency_contact,
        'emergency_contacts': json.loads(card.emergency_contacts) if card.emergency_contacts else [],
        'health_conditions': card.health_conditions, 'notes': card.notes, 'profile_picture': card.profile_picture
    }
    return render_template('user_data.html', user=user_data)

# Show QR code - restricted to owner only
@app.route('/show_qr/<int:card_id>')
@login_required
def show_qr(card_id):
    card = HealthCard.query.get_or_404(card_id)
    if card.user_id != current_user.id:
        flash('You do not have permission to view this QR code.', 'danger')
        return redirect(url_for('index'))
    return render_template('qr.html', qr_base64=card.qr_code, user_id=card.id)

# Main block - using port 5001 to avoid conflicts with other apps during testing
if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True, port=5001)