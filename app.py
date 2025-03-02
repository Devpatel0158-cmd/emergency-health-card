from flask import Flask, request, render_template, send_from_directory, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import sqlite3
import qrcode
import os
from io import BytesIO
import json

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'f8754ee9be88b3f0575e1e1b1a2271c9943f0948e94674ad')  # Use environment variable for secret key
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the database path relative to the app location
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'health_data.db')

# Initialize SQLite database
def init_db():
    print("Initializing database at:", DATABASE_PATH)  # Debug print
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    # Drop existing tables to ensure schema is applied
    c.execute('DROP TABLE IF EXISTS users_auth')
    c.execute('DROP TABLE IF EXISTS users')
    # Create tables with the updated schema
    c.execute('''CREATE TABLE users_auth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        age INTEGER,
        date_of_birth TEXT,
        height REAL,
        weight REAL,
        blood_type TEXT,
        allergies TEXT,
        medications TEXT,
        emergency_contact TEXT,
        emergency_contacts TEXT,
        health_conditions TEXT,
        notes TEXT,
        profile_picture TEXT,
        FOREIGN KEY (user_id) REFERENCES users_auth(id)
    )''')
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Route to serve uploaded images
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('static/uploads', filename)

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM users_auth WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user[2], password):
            login_user(User(user[0]))
            flash('Login Successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users_auth (email, password) VALUES (?, ?)', (email, password))
            conn.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists', 'danger')
        conn.close()
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
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute('SELECT id, name, blood_type FROM users WHERE user_id = ?', (current_user.id,))
        health_cards = c.fetchall()
        conn.close()
        
        health_cards_data = [{'id': card[0], 'name': card[1], 'blood_type': card[2]} for card in health_cards]
        return render_template('dashboard.html', health_cards=health_cards_data)
    return render_template('landing.html')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_health_card():
    if request.method == 'POST':
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
            if emergency_numbers[i]:  # Only add if number exists
                contact = {
                    "number": emergency_numbers[i],
                    "relation": emergency_relations[i] if i < len(emergency_relations) else ""
                }
                emergency_contacts.append(contact)
        
        emergency_contacts_json = json.dumps(emergency_contacts)
        emergency_contact = emergency_numbers[0] if emergency_numbers else ""
        
        health_conditions = request.form.get('health_conditions', '')
        notes = request.form.get('notes', '')

        # Handle profile picture upload
        profile_picture = request.files.get('profile_picture')
        profile_picture_path = ''
        if profile_picture:
            os.makedirs('static/uploads', exist_ok=True)
            profile_picture_path = f"static/uploads/{current_user.id}_{profile_picture.filename}"
            profile_picture.save(profile_picture_path)

        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO users (user_id, name, age, date_of_birth, height, weight, blood_type, 
                     allergies, medications, emergency_contact, emergency_contacts, health_conditions, 
                     notes, profile_picture)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (current_user.id, name, age, date_of_birth, height, weight, blood_type, 
                   allergies, medications, emergency_contact, emergency_contacts_json, health_conditions, 
                   notes, profile_picture_path))
        conn.commit()
        user_id = c.lastrowid
        conn.close()

        qr_url = f"http://127.0.0.1:5001/user/{user_id}"  # Will be updated to Vercel URL after deployment
        qr = qrcode.make(qr_url)
        qr_path = f"static/qr_codes/qr_{user_id}.png"
        os.makedirs(os.path.dirname(qr_path), exist_ok=True)
        qr.save(qr_path)

        return render_template('qr.html', qr_path=qr_path, user_id=user_id)
    return render_template('index.html')

@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_health_card(user_id):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ? AND user_id = ?', (user_id, current_user.id))
    user = c.fetchone()
    if not user:
        flash('Health card not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('index'))

    user_data = {
        'id': user[0],
        'name': user[2],
        'age': user[3],
        'date_of_birth': user[4] if len(user) > 4 else '',
        'height': user[5] if len(user) > 5 else '',
        'weight': user[6] if len(user) > 6 else '',
        'blood_type': user[7] if len(user) > 7 else '',
        'allergies': user[8] if len(user) > 8 else '',
        'medications': user[9] if len(user) > 9 else '',
        'emergency_contact': user[10] if len(user) > 10 else '',
        'emergency_contacts': json.loads(user[11]) if len(user) > 11 and user[11] else [],
        'health_conditions': user[12] if len(user) > 12 else '',
        'notes': user[13] if len(user) > 13 else '',
        'profile_picture': user[14] if len(user) > 14 else ''
    }

    if request.method == 'POST':
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
            if emergency_numbers[i]:  # Only add if number exists
                contact = {
                    "number": emergency_numbers[i],
                    "relation": emergency_relations[i] if i < len(emergency_relations) else ""
                }
                emergency_contacts.append(contact)
        
        emergency_contacts_json = json.dumps(emergency_contacts)
        emergency_contact = emergency_numbers[0] if emergency_numbers else ""
        
        health_conditions = request.form.get('health_conditions', '')
        notes = request.form.get('notes', '')

        # Handle profile picture upload
        profile_picture = request.files.get('profile_picture')
        profile_picture_path = user_data['profile_picture']
        if profile_picture:
            os.makedirs('static/uploads', exist_ok=True)
            profile_picture_path = f"static/uploads/{current_user.id}_{profile_picture.filename}"
            profile_picture.save(profile_picture_path)

        c.execute('''UPDATE users SET name = ?, age = ?, date_of_birth = ?, height = ?, weight = ?, blood_type = ?, 
                     allergies = ?, medications = ?, emergency_contact = ?, emergency_contacts = ?, 
                     health_conditions = ?, notes = ?, profile_picture = ?
                     WHERE id = ? AND user_id = ?''',
                  (name, age, date_of_birth, height, weight, blood_type, allergies, medications, 
                   emergency_contact, emergency_contacts_json, health_conditions, notes, profile_picture_path, 
                   user_id, current_user.id))
        conn.commit()

        # Generate a new QR code
        qr_url = f"http://127.0.0.1:5001/user/{user_id}"  # Will be updated to Vercel URL after deployment
        qr = qrcode.make(qr_url)
        qr_path = f"static/qr_codes/qr_{user_id}.png"
        os.makedirs(os.path.dirname(qr_path), exist_ok=True)
        qr.save(qr_path)

        conn.close()
        flash('Health card updated successfully!', 'success')
        return render_template('qr.html', qr_path=qr_path, user_id=user_id)

    conn.close()
    return render_template('edit_health_card.html', user=user_data)

@app.route('/user/<int:user_id>')
def get_user_data(user_id):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()

    if user:
        user_data = {
            'id': user[0],
            'name': user[2],
            'age': user[3],
            'date_of_birth': user[4] if len(user) > 4 else '',
            'height': user[5] if len(user) > 5 else '',
            'weight': user[6] if len(user) > 6 else '',
            'blood_type': user[7] if len(user) > 7 else '',
            'allergies': user[8] if len(user) > 8 else '',
            'medications': user[9] if len(user) > 9 else '',
            'emergency_contact': user[10] if len(user) > 10 else '',
            'emergency_contacts': json.loads(user[11]) if len(user) > 11 and user[11] else [],
            'health_conditions': user[12] if len(user) > 12 else '',
            'notes': user[13] if len(user) > 13 else '',
            'profile_picture': user[14] if len(user) > 14 else ''
        }
        return render_template('user_data.html', user=user_data)
    return "User not found", 404

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True, port=5001)
    print("Flask server started.")