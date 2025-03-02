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

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'f8754ee9be88b3f0575e1e1b1a2271c9943f0948e94674ad')
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# In-memory storage for demo purposes
users_auth = {}  # {user_id: {'email': ..., 'username': ..., 'password': ...}}
health_cards = {}  # {card_id: {...}}
next_user_id = 1
next_card_id = 1

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if int(user_id) in users_auth:
        return User(int(user_id))
    return None

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('email', '')
        password = request.form.get('password', '')
        if not identifier or not password:
            flash('Email/username and password are required.', 'danger')
            return redirect(url_for('login'))
        user = next((uid for uid, data in users_auth.items() if data['email'] == identifier or data['username'] == identifier), None)
        if user and bcrypt.check_password_hash(users_auth[user]['password'], password):
            login_user(User(user))
            flash('Login Successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid email/username or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    global next_user_id
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            # Validate required fields
            if not email or not username or not password:
                flash('Email, username, and password are required.', 'danger')
                return redirect(url_for('signup'))

            # Check for existing email or username
            if any(data['email'] == email for data in users_auth.values()):
                flash('Email already exists', 'danger')
                return redirect(url_for('signup'))
            if any(data['username'] == username for data in users_auth.values()):
                flash('Username already exists', 'danger')
                return redirect(url_for('signup'))

            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create new user
            user_id = next_user_id
            users_auth[user_id] = {'email': email, 'username': username, 'password': hashed_password}
            next_user_id += 1

            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in signup: {str(e)}", exc_info=True)
            flash('An error occurred while signing up. Please try again.', 'danger')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '')
        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('forgot_password'))
        flash('Password reset instructions sent to your email (simulated).', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        user_cards = [card for card in health_cards.values() if card['user_id'] == current_user.id]
        health_cards_data = [{'id': card['id'], 'name': card['name'], 'blood_type': card['blood_type']} for card in user_cards]
        user_username = users_auth[current_user.id]['username']
        return render_template('dashboard.html', health_cards=health_cards_data, user_username=user_username)
    return render_template('landing.html')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_health_card():
    global next_card_id
    if request.method == 'POST':
        try:
            # Validate and parse form data with defaults
            name = request.form.get('name', '').strip()
            age = int(request.form.get('age', 0)) if request.form.get('age') and request.form['age'].isdigit() else 0
            date_of_birth = request.form.get('date_of_birth', '')
            height = float(request.form.get('height', 0)) if request.form.get('height') and request.form['height'].replace('.', '', 1).isdigit() else None
            weight = float(request.form.get('weight', 0)) if request.form.get('weight') and request.form['weight'].replace('.', '', 1).isdigit() else None
            blood_type = request.form.get('blood_type', '').strip()
            allergies = request.form.get('allergies', '')
            medications = request.form.get('medications', '')
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
            emergency_contacts_json = json.dumps(emergency_contacts)
            emergency_contact = emergency_numbers[0] if emergency_numbers else ""
            health_conditions = request.form.get('health_conditions', '')
            notes = request.form.get('notes', '')
            # New fields with defaults
            gender = request.form.get('gender', '')
            address = request.form.get('address', '')
            contact_number = request.form.get('contact_number', '')
            eye_color = request.form.get('eye_color', '')
            hair_color = request.form.get('hair_color', '')
            past_surgeries = request.form.get('past_surgeries', '')
            chronic_illnesses = request.form.get('chronic_illnesses', '')
            family_medical_history = request.form.get('family_medical_history', '')
            immunization_history = request.form.get('immunization_history', '')
            hospitalization_history = request.form.get('hospitalization_history', '')
            smoking_status = request.form.get('smoking_status', '')
            alcohol_consumption = request.form.get('alcohol_consumption', '')
            drug_use = request.form.get('drug_use', '')
            exercise_routine = request.form.get('exercise_routine', '')
            diet_preferences = request.form.get('diet_preferences', '')
            primary_care_physician = request.form.get('primary_care_physician', '')
            insurance_info = request.form.get('insurance_info', '')
            blood_pressure = request.form.get('blood_pressure', '')
            heart_rate = int(request.form.get('heart_rate', 0)) if request.form.get('heart_rate') and request.form['heart_rate'].isdigit() else None
            oxygen_saturation = int(request.form.get('oxygen_saturation', 0)) if request.form.get('oxygen_saturation') and request.form['oxygen_saturation'].isdigit() else None

            # Validate required fields
            if not name or not age or not blood_type:
                flash('Name, age, and blood type are required.', 'danger')
                return redirect(url_for('create_health_card'))

            card_id = next_card_id
            health_cards[card_id] = {
                'id': card_id,
                'user_id': current_user.id,
                'name': name,
                'age': age,
                'date_of_birth': date_of_birth,
                'height': height,
                'weight': weight,
                'blood_type': blood_type,
                'allergies': allergies,
                'medications': medications,
                'emergency_contact': emergency_contact,
                'emergency_contacts': emergency_contacts_json,
                'health_conditions': health_conditions,
                'notes': notes,
                'profile_picture': None,
                'qr_code': None,
                'gender': gender,
                'address': address,
                'contact_number': contact_number,
                'eye_color': eye_color,
                'hair_color': hair_color,
                'past_surgeries': past_surgeries,
                'chronic_illnesses': chronic_illnesses,
                'family_medical_history': family_medical_history,
                'immunization_history': immunization_history,
                'hospitalization_history': hospitalization_history,
                'smoking_status': smoking_status,
                'alcohol_consumption': alcohol_consumption,
                'drug_use': drug_use,
                'exercise_routine': exercise_routine,
                'diet_preferences': diet_preferences,
                'primary_care_physician': primary_care_physician,
                'insurance_info': insurance_info,
                'blood_pressure': blood_pressure,
                'heart_rate': heart_rate,
                'oxygen_saturation': oxygen_saturation
            }
            next_card_id += 1

            qr_url = f"https://emergency-health-card.vercel.app/user/{card_id}"
            return render_template('qr.html', qr_url=qr_url, user_id=card_id)
        except ValueError as ve:
            logger.error(f"ValueError in create_health_card: {str(ve)}", exc_info=True)
            flash('Invalid input data (e.g., numbers). Please check your entries.', 'danger')
            return redirect(url_for('create_health_card'))
        except Exception as e:
            logger.error(f"Error in create_health_card: {str(e)}", exc_info=True)
            flash('An error occurred while creating the health card.', 'danger')
            return redirect(url_for('index'))
    return render_template('index.html')

@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_health_card(user_id):
    user_id = int(user_id)
    if user_id not in health_cards or health_cards[user_id]['user_id'] != current_user.id:
        flash('Health card not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('index'))

    user_data = health_cards[user_id]

    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            age = int(request.form.get('age', 0)) if request.form.get('age') and request.form['age'].isdigit() else 0
            date_of_birth = request.form.get('date_of_birth', '')
            height = float(request.form.get('height', 0)) if request.form.get('height') and request.form['height'].replace('.', '', 1).isdigit() else None
            weight = float(request.form.get('weight', 0)) if request.form.get('weight') and request.form['weight'].replace('.', '', 1).isdigit() else None
            blood_type = request.form.get('blood_type', '').strip()
            allergies = request.form.get('allergies', '')
            medications = request.form.get('medications', '')
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
            emergency_contacts_json = json.dumps(emergency_contacts)
            emergency_contact = emergency_numbers[0] if emergency_numbers else ""
            health_conditions = request.form.get('health_conditions', '')
            notes = request.form.get('notes', '')
            # New fields with defaults
            gender = request.form.get('gender', '')
            address = request.form.get('address', '')
            contact_number = request.form.get('contact_number', '')
            eye_color = request.form.get('eye_color', '')
            hair_color = request.form.get('hair_color', '')
            past_surgeries = request.form.get('past_surgeries', '')
            chronic_illnesses = request.form.get('chronic_illnesses', '')
            family_medical_history = request.form.get('family_medical_history', '')
            immunization_history = request.form.get('immunization_history', '')
            hospitalization_history = request.form.get('hospitalization_history', '')
            smoking_status = request.form.get('smoking_status', '')
            alcohol_consumption = request.form.get('alcohol_consumption', '')
            drug_use = request.form.get('drug_use', '')
            exercise_routine = request.form.get('exercise_routine', '')
            diet_preferences = request.form.get('diet_preferences', '')
            primary_care_physician = request.form.get('primary_care_physician', '')
            insurance_info = request.form.get('insurance_info', '')
            blood_pressure = request.form.get('blood_pressure', '')
            heart_rate = int(request.form.get('heart_rate', 0)) if request.form.get('heart_rate') and request.form['heart_rate'].isdigit() else None
            oxygen_saturation = int(request.form.get('oxygen_saturation', 0)) if request.form.get('oxygen_saturation') and request.form['oxygen_saturation'].isdigit() else None

            # Validate required fields
            if not name or not age or not blood_type:
                flash('Name, age, and blood type are required.', 'danger')
                return redirect(url_for('edit_health_card', user_id=user_id))

            health_cards[user_id] = {
                'id': user_id,
                'user_id': current_user.id,
                'name': name,
                'age': age,
                'date_of_birth': date_of_birth,
                'height': height,
                'weight': weight,
                'blood_type': blood_type,
                'allergies': allergies,
                'medications': medications,
                'emergency_contact': emergency_contact,
                'emergency_contacts': emergency_contacts_json,
                'health_conditions': health_conditions,
                'notes': notes,
                'profile_picture': None,
                'qr_code': None,
                'gender': gender,
                'address': address,
                'contact_number': contact_number,
                'eye_color': eye_color,
                'hair_color': hair_color,
                'past_surgeries': past_surgeries,
                'chronic_illnesses': chronic_illnesses,
                'family_medical_history': family_medical_history,
                'immunization_history': immunization_history,
                'hospitalization_history': hospitalization_history,
                'smoking_status': smoking_status,
                'alcohol_consumption': alcohol_consumption,
                'drug_use': drug_use,
                'exercise_routine': exercise_routine,
                'diet_preferences': diet_preferences,
                'primary_care_physician': primary_care_physician,
                'insurance_info': insurance_info,
                'blood_pressure': blood_pressure,
                'heart_rate': heart_rate,
                'oxygen_saturation': oxygen_saturation
            }

            qr_url = f"https://emergency-health-card.vercel.app/user/{user_id}"
            flash('Health card updated successfully!', 'success')
            return render_template('qr.html', qr_url=qr_url, user_id=user_id)
        except ValueError as ve:
            logger.error(f"ValueError in edit_health_card: {str(ve)}", exc_info=True)
            flash('Invalid input data (e.g., numbers). Please check your entries.', 'danger')
            return redirect(url_for('edit_health_card', user_id=user_id))
        except Exception as e:
            logger.error(f"Error in edit_health_card: {str(e)}", exc_info=True)
            flash(f'An error occurred: {str(e)}. Please try again.', 'danger')
            return redirect(url_for('edit_health_card', user_id=user_id))
    return render_template('edit_health_card.html', user=user_data)

@app.route('/user/<int:user_id>')
def get_user_data(user_id):
    user_id = int(user_id)
    if user_id not in health_cards:
        return "User not found", 404

    user = health_cards[user_id]
    user_data = {
        'id': user['id'],
        'name': user['name'],
        'age': user['age'],
        'date_of_birth': user['date_of_birth'],
        'height': user['height'],
        'weight': user['weight'],
        'blood_type': user['blood_type'],
        'allergies': user['allergies'],
        'medications': user['medications'],
        'emergency_contact': user['emergency_contact'],
        'emergency_contacts': json.loads(user['emergency_contacts']) if user['emergency_contacts'] else [],
        'health_conditions': user['health_conditions'],
        'notes': user['notes'],
        'profile_picture': user['profile_picture'],
        'gender': user['gender'],
        'address': user['address'],
        'contact_number': user['contact_number'],
        'eye_color': user['eye_color'],
        'hair_color': user['hair_color'],
        'past_surgeries': user['past_surgeries'],
        'chronic_illnesses': user['chronic_illnesses'],
        'family_medical_history': user['family_medical_history'],
        'immunization_history': user['immunization_history'],
        'hospitalization_history': user['hospitalization_history'],
        'smoking_status': user['smoking_status'],
        'alcohol_consumption': user['alcohol_consumption'],
        'drug_use': user['drug_use'],
        'exercise_routine': user['exercise_routine'],
        'diet_preferences': user['diet_preferences'],
        'primary_care_physician': user['primary_care_physician'],
        'insurance_info': user['insurance_info'],
        'blood_pressure': user['blood_pressure'],
        'heart_rate': user['heart_rate'],
        'oxygen_saturation': user['oxygen_saturation']
    }
    return render_template('user_data.html', user=user_data)

@app.route('/show_qr/<int:card_id>')
@login_required
def show_qr(card_id):
    if card_id not in health_cards or health_cards[card_id]['user_id'] != current_user.id:
        flash('You do not have permission to view this QR code.', 'danger')
        return redirect(url_for('index'))
    qr_url = f"https://emergency-health-card.vercel.app/user/{card_id}"
    return render_template('qr.html', qr_url=qr_url, user_id=card_id)

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True, port=5001)
    print("Flask server started.")