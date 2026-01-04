"""
Authentication Module
Handles user registration, login, and session management
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging

logger = logging.getLogger(__name__)


# Create Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

# Login manager instance (initialized in init_auth)
login_manager = LoginManager()

# Limiter reference (set during init_auth)
limiter = None


class User(UserMixin):
    """User class for Flask-Login."""
    
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def hash_password(password):
        return generate_password_hash(password)


def init_auth(app, get_db_func, limiter_instance=None):
    """Initialize authentication with Flask app."""
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Store get_db function for use in this module
    global get_db, limiter
    get_db = get_db_func
    limiter = limiter_instance
    
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login."""
        conn, is_postgres = get_db()
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        
        cursor.execute(
            f'SELECT id, username, password_hash FROM users WHERE id = {placeholder}',
            (int(user_id),)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(id=row[0], username=row[1], password_hash=row[2])
        return None
    
    # Register blueprint
    app.register_blueprint(auth_bp)
    
    # Apply strict rate limiting to auth routes after blueprint registration
    if limiter:
        limiter.limit("5 per minute", methods=["POST"])(login)
        limiter.limit("3 per minute", methods=["POST"])(register)


def init_users_table(conn, is_postgres):
    """Create users table if it doesn't exist."""
    cursor = conn.cursor()
    
    if is_postgres:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    
    conn.commit()


def add_user_id_to_todos(conn, is_postgres):
    """Add user_id column to todos table if it doesn't exist."""
    cursor = conn.cursor()
    
    try:
        if is_postgres:
            cursor.execute('ALTER TABLE todos ADD COLUMN user_id INTEGER REFERENCES users(id)')
        else:
            cursor.execute('ALTER TABLE todos ADD COLUMN user_id INTEGER')
        conn.commit()
    except:
        conn.rollback()  # Column already exists


def add_user_id_to_google_tokens(conn, is_postgres):
    """Add user_id column to google_tokens table if it doesn't exist."""
    cursor = conn.cursor()
    
    try:
        if is_postgres:
            cursor.execute('ALTER TABLE google_tokens ADD COLUMN user_id INTEGER REFERENCES users(id)')
        else:
            cursor.execute('ALTER TABLE google_tokens ADD COLUMN user_id INTEGER')
        conn.commit()
    except:
        conn.rollback()  # Column already exists


def login_required_api(f):
    """Decorator for API routes that require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        conn, is_postgres = get_db()
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        
        cursor.execute(
            f'SELECT id, username, password_hash FROM users WHERE username = {placeholder}',
            (username,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user = User(id=row[0], username=row[1], password_hash=row[2])
            if user.check_password(password):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
        
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('register.html')
        
        if len(username) < 3 or len(username) > 80:
            flash('Username must be between 3 and 80 characters.', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        conn, is_postgres = get_db()
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        
        # Check if username exists
        cursor.execute(
            f'SELECT id FROM users WHERE username = {placeholder}',
            (username,)
        )
        if cursor.fetchone():
            conn.close()
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        # Create user
        password_hash = User.hash_password(password)
        cursor.execute(
            f'INSERT INTO users (username, password_hash) VALUES ({placeholder}, {placeholder})',
            (username, password_hash)
        )
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
