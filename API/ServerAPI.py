import uuid
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
import logging
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = '9318447431938K'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keys.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure Redis for Flask-Limiter
redis_connection = Redis(host='localhost', port=6379)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="redis://localhost:6379",
    default_limits=["200 per day", "50 per hour"]
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
    user = db.relationship('User', uselist=False, backref='license_key')

    def days_left(self):
        if self.ends:
            return (self.ends - datetime.utcnow()).days
        return None

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    key_id = db.Column(db.Integer, db.ForeignKey('license_key.id'), nullable=True)

def generate_license_key(length):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_hwid():
    return str(uuid.uuid4())

def check_authorization():
    if not session.get('logged_in'):
        logging.warning("Unauthorized access attempt.")
        return jsonify({'message': 'Unauthorized'}), 403
    if not session.get('is_admin'):
        logging.warning("Admin privileges required.")
        return jsonify({'message': 'Admin privileges required'}), 403
    return None

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    keys = LicenseKey.query.all()
    return render_template('home.html', keys=keys)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/api_documentation')
def api_documentation():
    return render_template('api.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hwid = request.form.get('hwid')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = user.is_admin

            if user.is_admin:
                flash('Admin login successful.', 'success')
                return redirect(url_for('show_flash', delay=2, next='index'))
            else:
                flash('Login successful.', 'success')
                return redirect(url_for('show_flash', delay=2, next='home'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@limiter.limit("50 per minute")
def logout():
    session['logged_in'] = False
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('show_flash', delay=2, next='login'))

@app.route('/show_flash/<int:delay>/<next>')
def show_flash(delay, next):
    return render_template('show_flash.html', delay=delay, next=next)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    key = data['key']
    hwid = data['hwid']
    ip = request.remote_addr

    license_key = LicenseKey.query.filter_by(key=key, authed=False).first()
    if not license_key:
        return jsonify({'message': 'Invalid or already activated key'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, license_key=license_key)
    db.session.add(new_user)

    license_key.hwid = hwid
    license_key.ip = ip
    license_key.authed = True
    license_key.created = datetime.utcnow()
    license_key.ends = license_key.created + timedelta(days=license_key.length)

    db.session.commit()

    return jsonify({'message': 'User registered and key activated successfully'})

@app.route('/verify_user', methods=['POST'])
@limiter.limit("5 per minute")
def verify_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    hwid = data['hwid']

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid password'}), 400

    license_key = user.license_key
    if not license_key:
        return jsonify({'message': 'License key not found'}), 404

    if license_key.hwid != hwid:
        return jsonify({'message': 'Invalid HWID'}), 400

    if license_key.ends < datetime.utcnow() or license_key.length <= 0:
        return jsonify({'message': 'License key has expired'}), 400

    return jsonify({
        'message': 'User verified successfully',
        'days_left': license_key.days_left(),
        'key': license_key.key,
        'ends': license_key.ends
    })

@app.route('/reset_hwid/<license_key>', methods=['POST'])
@limiter.limit("5 per minute")
def reset_hwid(license_key):
    auth_check = check_authorization()
    if auth_check:
        return auth_check

    license_key_entry = LicenseKey.query.filter_by(key=license_key).first()
    if not license_key_entry:
        return jsonify({'message': 'License key not found'}), 404

    license_key_entry.hwid = None
    db.session.commit()

    return jsonify({'message': 'HWID reset successfully'})

@app.route('/update_time/<license_key>', methods=['POST'])
@limiter.limit("5 per minute")
def update_time(license_key):
    auth_check = check_authorization()
    if auth_check:
        return auth_check

    data = request.get_json()
    new_length = data.get('length')
    if new_length is None or not isinstance(new_length, int):
        return jsonify({'message': 'Invalid length'}), 400

    license_key_entry = LicenseKey.query.filter_by(key=license_key).first()
    if not license_key_entry:
        return jsonify({'message': 'License key not found'}), 404

    license_key_entry.length = new_length
    license_key_entry.ends = license_key_entry.created + timedelta(days=new_length)
    db.session.commit()

    return jsonify({'message': 'Validity length updated successfully'})

@app.route('/delete_key/<license_key>', methods=['DELETE'])
@limiter.limit("5 per minute")
def delete_key(license_key):
    auth_check = check_authorization()
    if auth_check:
        return auth_check

    license_key_entry = LicenseKey.query.filter_by(key=license_key).first()
    if not license_key_entry:
        return jsonify({'message': 'License key not found'}), 404

    db.session.delete(license_key_entry)
    db.session.commit()

    return jsonify({'message': 'License key deleted successfully'})

@app.route('/get_hwid', methods=['GET'])
def get_hwid():
    return jsonify({'hwid': generate_hwid()})

@app.route('/check_session')
def check_session():
    if not session.get('logged_in'):
        return '', 403
    return '', 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
