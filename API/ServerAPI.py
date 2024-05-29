import os
from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
import random
import string
import click

app = Flask(__name__)
app.config['SECRET_KEY'] = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keys.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure Redis for Flask-Limiter
redis_connection = Redis(host='localhost', port=6379)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="redis://localhost:6379",
    default_limits=["500 per day", "100 per hour"]
)

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    length = db.Column(db.Integer, nullable=False)
    created = db.Column(db.DateTime, nullable=True)
    ends = db.Column(db.DateTime, nullable=True)
    hwid = db.Column(db.String(100), nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    authed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='license_keys', uselist=False)
    database_id = db.Column(db.Integer, db.ForeignKey('database.id'), nullable=True)
    database = db.relationship('Database', backref='license_keys')

    def days_left(self):
        if self.ends:
            return (self.ends - datetime.utcnow()).days
        return None

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    databases = db.relationship('Database', backref='owner', lazy=True)

class Database(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def generate_license_key(length=25):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def check_authorization():
    if 'logged_in' not in session or not session.get('is_admin'):
        return jsonify({'message': 'Unauthorized access'}), 403
    return None

def create_user_directory(username):
    user_dir = os.path.join('User-Databases', username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
        print(f"Created user directory: {user_dir}")  # Debug statement
    return user_dir

@app.cli.command('create-admin')
@click.argument('username')
@click.argument('password')
@click.argument('email')
def create_admin(username, password, email):
    """Create a new admin user."""
    hashed_password = generate_password_hash(password, method='sha256')
    new_admin = User(username=username, password=hashed_password, email=email, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    click.echo(f'Admin user {username} created successfully.')

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['username'] = user.username
            return redirect(url_for('key_management'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        math_answer = int(request.form['math_answer'])
        is_admin = False  # Registration should not allow setting admin status

        # Validate math answer
        correct_answer = session['num1'] + session['num2']
        if math_answer != correct_answer:
            flash('Incorrect math answer. Please try again.', 'danger')
            return redirect(url_for('register'))

        if not username or not password or not email:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists', 'danger')
            elif existing_user.email == email:
                flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(
            username=username,
            password=hashed_password,
            email=email,
            is_admin=is_admin
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    # Generate math question for GET request
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    session['num1'] = num1
    session['num2'] = num2

    return render_template('register.html')

@app.route('/api_documentation')
def api_documentation():
    return render_template('api.html')

@app.route('/verify_user', methods=['POST'])
def verify_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    if hwid:
        license_key = LicenseKey.query.filter_by(user_id=user.id, hwid=hwid).first()
        if license_key:
            if not license_key.authed:
                license_key.authed = True
                license_key.created = datetime.utcnow()
                license_key.ends = datetime.utcnow() + timedelta(days=license_key.length)
                db.session.commit()

            return jsonify({'message': 'User verified', 'key': license_key.key}), 200

    return jsonify({'message': 'Invalid hardware ID'}), 401

@app.route('/generate_database', methods=['POST'])
def generate_database():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    user_id = session['user_id']
    data = request.get_json()
    db_name = data.get('name')

    if not db_name:
        return jsonify({'success': False, 'message': 'Database name is required'})

    user = User.query.get(user_id)
    user_dir = create_user_directory(user.username)
    db_path = os.path.join(user_dir, f"{db_name}.db")

    if os.path.exists(db_path):
        return jsonify({'success': False, 'message': 'Database already exists'})

    new_db = Database(name=db_name, user_id=user_id)
    db.session.add(new_db)
    db.session.commit()

    open(db_path, 'w').close()  # Create an empty file to represent the new database
    print(f"Created database file: {db_path}")  # Debug statement

    return jsonify({'success': True, 'message': 'Database created successfully'})

@app.route('/delete_database/<int:db_id>', methods=['DELETE'])
def delete_database(db_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    user_id = session['user_id']
    database = Database.query.filter_by(id=db_id, user_id=user_id).first()

    if not database:
        return jsonify({'success': False, 'message': 'Database not found or unauthorized'})

    user = User.query.get(user_id)
    user_dir = create_user_directory(user.username)
    db_path = os.path.join(user_dir, f"{database.name}.db")

    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Deleted database file: {db_path}")  # Debug statement

    db.session.delete(database)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Database deleted successfully'})

@app.route('/list_databases', methods=['GET'])
def list_databases():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    user_id = session['user_id']
    user = User.query.get(user_id)
    databases = Database.query.filter_by(user_id=user_id).all()

    db_list = [{'id': db.id, 'name': db.name} for db in databases]

    # Add Main Database for admin users only
    if user.is_admin:
        main_database = {'id': 0, 'name': 'Main Database'}
        if not any(db['id'] == 0 for db in db_list):  # Avoid duplicate entries
            db_list.insert(0, main_database)

    return jsonify({'success': True, 'databases': db_list})

@app.route('/select_database/<int:db_id>', methods=['POST'])
def select_database(db_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    selected_db = Database.query.filter_by(id=db_id, user_id=session['user_id']).first()
    if not selected_db and db_id != 0:  # Allow access to Main Database for admins
        return jsonify({'success': False, 'message': 'Unauthorized access'})

    session['selected_db'] = db_id
    return jsonify({'success': True, 'message': f'Database {db_id if db_id != 0 else "Main Database"} selected'})

@app.route('/fetch_database_entries', methods=['GET'])
def fetch_database_entries():
    if 'user_id' not in session or 'selected_db' not in session:
        return jsonify({'success': False, 'message': 'User not logged in or database not selected'})

    selected_db = session['selected_db']
    entries = LicenseKey.query.filter_by(database_id=selected_db).all()

    entry_list = [{'id': entry.id, 'key': entry.key, 'length': entry.length, 'created': entry.created, 'ends': entry.ends, 'hwid': entry.hwid, 'ip': entry.ip, 'authed': entry.authed} for entry in entries]

    return jsonify({'success': True, 'entries': entry_list})

@app.route('/fetch_user_credentials', methods=['GET'])
def fetch_user_credentials():
    if 'user_id' not in session or 'selected_db' not in session:
        return jsonify({'success': False, 'message': 'User not logged in or database not selected'})

    if session['selected_db'] != 0:
        return jsonify({'success': False, 'message': 'Invalid database selected'})

    users = User.query.all()
    user_list = [{'id': user.id, 'username': user.username, 'password': user.password, 'is_admin': user.is_admin} for user in users]

    return jsonify({'success': True, 'users': user_list})

@app.route('/generate_keys', methods=['POST'])
@limiter.limit("5 per minute")
def generate_keys():
    if 'selected_db' not in session:
        return jsonify({'message': 'No database selected'}), 400

    selected_db = session['selected_db']
    user_id = session['user_id']
    is_admin = session.get('is_admin')

    if not is_admin:
        database = Database.query.filter_by(id=selected_db, user_id=user_id).first()
        if not database:
            return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()
    try:
        number_of_keys = int(data.get('number_of_keys'))
        key_length = int(data.get('key_length'))
        validity_length = int(data.get('validity_length'))
    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid input, integers required'}), 400

    if not number_of_keys or not key_length or not validity_length:
        return jsonify({'message': 'Missing required parameters'}), 400

    generated_keys = []

    for _ in range(number_of_keys):
        key = generate_license_key(key_length)
        new_key = LicenseKey(
            key=key, 
            length=validity_length, 
            created=datetime.utcnow(), 
            ends=None,
            user_id=user_id, 
            database_id=selected_db
        )
        db.session.add(new_key)
        generated_keys.append(key)

    db.session.commit()

    return jsonify({'message': f'{number_of_keys} license keys generated successfully.', 'keys': generated_keys})

@app.route('/reset_hwid/<int:key_id>', methods=['POST'])
def reset_hwid(key_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    key = LicenseKey.query.get(key_id)
    if key:
        key.hwid = None
        db.session.commit()
        return jsonify({'success': True, 'message': 'HWID reset successfully'})
    return jsonify({'success': False, 'message': 'Key not found'})

@app.route('/delete_key/<int:key_id>', methods=['DELETE'])
def delete_key(key_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    key = LicenseKey.query.get(key_id)
    if key:
        db.session.delete(key)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Key deleted successfully'})
    return jsonify({'success': False, 'message': 'Key not found'})

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session or 'selected_db' not in session:
        return jsonify({'success': False, 'message': 'User not logged in or database not selected'})

    if session['selected_db'] != 0:
        return jsonify({'success': False, 'message': 'Invalid database selected'})

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({'success': False, 'message': 'User not found'})

    # Delete all associated databases
    associated_databases = Database.query.filter_by(user_id=user_id).all()
    for db_entry in associated_databases:
        db_path = os.path.join('User-Databases', f"user_{user_to_delete.username}", f"{db_entry.name}.db")
        if os.path.exists(db_path):
            os.remove(db_path)
        db.session.delete(db_entry)

    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'success': True, 'message': 'User and associated databases deleted successfully'})

@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    if 'user_id' not in session or 'selected_db' not in session:
        return jsonify({'success': False, 'message': 'User not logged in or database not selected'})

    if session['selected_db'] != 0:
        return jsonify({'success': False, 'message': 'Invalid database selected'})

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})

    if username:
        user.username = username
    if password:
        user.password = generate_password_hash(password, method='sha256')

    db.session.commit()

    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/edit_validity_length/<int:key_id>', methods=['POST'])
def edit_validity_length(key_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    data = request.get_json()
    new_validity_length = data.get('validity_length')
    key = LicenseKey.query.get(key_id)
    if key and new_validity_length:
        key.ends = datetime.utcnow() + timedelta(days=new_validity_length)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Validity length updated successfully'})
    return jsonify({'success': False, 'message': 'Invalid input or key not found'})

@app.route('/get_hwid', methods=['GET'])
def get_hwid():
    return jsonify({'hwid'})

@app.route('/check_session')
def check_session():
    if not session.get('logged_in'):
        return '', 403
    return '', 200

@app.route('/key_management')
def key_management():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    user_id = session['user_id']
    is_admin = session.get('is_admin')
    databases = []

    try:
        if is_admin:
            all_databases = Database.query.all()
            databases = [{'id': db.id, 'name': db.name} for db in all_databases]
        else:
            user_databases = Database.query.filter_by(user_id=user_id).all()
            databases = [{'id': db.id, 'name': db.name} for db in user_databases]

        keys = []
        if 'selected_db' in session:
            selected_db = session['selected_db']
            keys = LicenseKey.query.filter_by(database_id=selected_db).all()

        print(f"User ID: {user_id}")
        print(f"Is Admin: {is_admin}")
        print(f"Databases: {databases}")
    except Exception as e:
        print(f"Error fetching databases: {e}")
        return render_template('error.html', message="An error occurred while fetching databases."), 500

    return render_template('key_management.html', databases=databases, is_admin=is_admin, keys=keys)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8000)
