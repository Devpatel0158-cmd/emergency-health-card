from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import qrcode
import os
import base64
from io import BytesIO
import json
import logging

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'f8754ee9be88b3f0575e1e1b1a2271c9943f0948e94674ad')
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Simulate user data in memory for demo purposes
users_auth = {}  # Stores user authentication data: {user_id: {'email': ..., 'password': ...}}
users = {}       # Stores health card data: {user_id: {...}}
next_user_id = 1
next_health_card_id = 1

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
        email = request.form['email']
        password = request.form['password']
        user = next((uid for uid, data in users_auth.items() if data['email'] == email), None)
        if user and bcrypt.check_password_hash(users_auth[user]['password'], password):
            login_user(User(user))
            flash('Login Successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    global next_user_id
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if any(data['email'] == email for data in users_auth.values()):
            flash('Email already exists', 'danger')
        else:
            user_id = next_user_id
            users_auth[user_id] = {'email': email, 'password': password}
            next_user_id += 1
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Simulate password reset (in production, send an email with a reset link)
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
        health_cards = [card for card in users.values() if card['user_id'] == current_user.id]
        health_cards_data = [{'id': card['id'], 'name': card['name'], 'blood_type': card['blood_type']} for card in health_cards]
        return render_template('dashboard.html', health_cards=health_cards_data)
    return render_template('landing.html')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_health_card():
    global next_health_card_id
    if request.method == 'POST':
        try:
            name = request.form['name']
            age = request.form['age']
            date_of_birth = request.form.get('date_of_birth', '')
            height = float(request.form['height']) if request.form.get('height') else None
            weight = float(request.form['weight']) if request.form.get('weight') else None
            blood_type = request.form['blood_type']
            allergies = request.form.get('allergies', '')
            medications = request.form.get('medications', '')
            
            # Process multiple emergency contacts
            emergency_numbers = request.form.getlist('emergency_contact_number[]')
            emergency_relations = request.form.getlist('emergency_contact_relation[]')
            emergency_contacts = []
            
            for i in range(len(emergency_numbers)):
                if emergency_numbers[i]:
                    contact = {
                        "number": emergency_numbers[i],
                        "relation": emergency_relations[i] if i < len(emergency_relations) else ""
                    }
                    emergency_contacts.append(contact)
            
            emergency_contacts_json = json.dumps(emergency_contacts)
            emergency_contact = emergency_numbers[0] if emergency_numbers else ""
            
            health_conditions = request.form.get('health_conditions', '')
            notes = request.form.get('notes', '')

            user_id = next_health_card_id
            users[user_id] = {
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
                'profile_picture': None  # Removed profile picture support
            }
            next_health_card_id += 1

            # Generate QR code with the correct Vercel URL
            qr_url = f"https://emergency-health-card.vercel.app/user/{user_id}"
            logger.debug(f"Generating QR code for URL: {qr_url}")
            qr = qrcode.make(qr_url)
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')  # Use base64 encoding
            
            return render_template('qr.html', qr_base64=qr_base64, user_id=user_id)
        except Exception as e:
            logger.error(f"Error in create_health_card: {str(e)}", exc_info=True)
            flash('An error occurred while generating the QR code.', 'danger')
            return redirect(url_for('index'))
    return render_template('index.html')

@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_health_card(user_id):
    user_id = int(user_id)
    if user_id not in users or users[user_id]['user_id'] != current_user.id:
        flash('Health card not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('index'))

    user_data = users[user_id]

    if request.method == 'POST':
        try:
            name = request.form['name']
            age = request.form['age']
            date_of_birth = request.form.get('date_of_birth', '')
            height = float(request.form['height']) if request.form.get('height') else None
            weight = float(request.form['weight']) if request.form.get('weight') else None
            blood_type = request.form['blood_type']
            allergies = request.form.get('allergies', '')
            medications = request.form.get('medications', '')
            
            # Process multiple emergency contacts
            emergency_numbers = request.form.getlist('emergency_contact_number[]')
            emergency_relations = request.form.getlist('emergency_contact_relation[]')
            emergency_contacts = []
            
            for i in range(len(emergency_numbers)):
                if emergency_numbers[i]:
                    contact = {
                        "number": emergency_numbers[i],
                        "relation": emergency_relations[i] if i < len(emergency_relations) else ""
                    }
                    emergency_contacts.append(contact)
            
            emergency_contacts_json = json.dumps(emergency_contacts)
            emergency_contact = emergency_numbers[0] if emergency_numbers else ""
            
            health_conditions = request.form.get('health_conditions', '')
            notes = request.form.get('notes', '')

            users[user_id] = {
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
                'profile_picture': None  # Removed profile picture support
            }

            # Generate QR code with the correct Vercel URL
            qr_url = f"https://emergency-health-card.vercel.app/user/{user_id}"
            logger.debug(f"Generating QR code for URL: {qr_url}")
            qr = qrcode.make(qr_url)
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')  # Use base64 encoding

            flash('Health card updated successfully!', 'success')
            return render_template('qr.html', qr_base64=qr_base64, user_id=user_id)
        except Exception as e:
            logger.error(f"Error in edit_health_card: {str(e)}", exc_info=True)
            flash('An error occurred while generating the QR code.', 'danger')
            return redirect(url_for('index'))

    return render_template('edit_health_card.html', user=user_data)

@app.route('/user/<int:user_id>')
def get_user_data(user_id):
    user_id = int(user_id)
    if user_id not in users:
        return "User not found", 404

    user = users[user_id]
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
        'profile_picture': None  # Removed profile picture support
    }
    return render_template('user_data.html', user=user_data)

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True, port=5001)
    print("Flask server started.")