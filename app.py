"""
Simple To-Do List Application
Flask backend with PostgreSQL database
"""

import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, session, flash
from datetime import datetime
from urllib.parse import urlparse
import secrets
import bleach

import google_calendar as gcal
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_login import login_required, current_user
import auth
import crypto_utils
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Allowed HTML tags and attributes for rich-text notes (Quill editor output)
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 's', 'a', 'ul', 'ol', 'li', 'span']
ALLOWED_ATTRS = {'a': ['href', 'target'], 'span': ['class']}

# Input validation limits
MAX_TEXT_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 2000
MAX_NOTES_LENGTH = 10000


def validate_todo_input(text=None, description=None, notes=None, deadline=None):
    """
    Validate todo input fields.
    Returns (is_valid, error_message) tuple.
    """
    if text is not None:
        if not text or not text.strip():
            return False, 'Text is required'
        if len(text) > MAX_TEXT_LENGTH:
            return False, f'Text must be {MAX_TEXT_LENGTH} characters or less'
    
    if description is not None and len(description) > MAX_DESCRIPTION_LENGTH:
        return False, f'Description must be {MAX_DESCRIPTION_LENGTH} characters or less'
    
    if notes is not None and len(notes) > MAX_NOTES_LENGTH:
        return False, f'Notes must be {MAX_NOTES_LENGTH} characters or less'
    
    if deadline is not None and deadline:
        # Basic ISO datetime format validation
        import re
        if not re.match(r'^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?)?$', deadline):
            return False, 'Invalid deadline format'
    
    return True, None


def sanitize_html(html_content):
    """Sanitize HTML content to prevent XSS attacks."""
    if not html_content:
        return html_content
    return bleach.clean(
        html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        strip=True
    )


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Session cookie security configuration
is_production = os.environ.get('FLASK_ENV') == 'production'
app.config.update(
    SESSION_COOKIE_SECURE=is_production,  # Only send over HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute", "50 per second"],
    storage_uri="memory://",
)


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    logger.warning(f"Rate limit exceeded: {get_remote_address()}")
    return jsonify({'error': 'Too many requests. Please slow down.'}), 429

# Security Headers via Flask-Talisman
# Content Security Policy allowing our CDN resources
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "'unsafe-eval'",  # Required for Quill.js editor functionality
        'https://cdn.quilljs.com',
        'https://cdnjs.cloudflare.com',
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",  # Required for Quill editor inline styles
        'https://cdn.quilljs.com',
        'https://fonts.googleapis.com',
    ],
    'font-src': [
        "'self'",
        'https://fonts.gstatic.com',
    ],
    'img-src': ["'self'", 'data:'],
    'connect-src': ["'self'", 'https://cdn.quilljs.com'],
}

talisman = Talisman(
    app,
    force_https=is_production,
    strict_transport_security=is_production,
    strict_transport_security_max_age=31536000,  # 1 year
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    frame_options='DENY',
    x_content_type_options=True,
    x_xss_protection=True,
    referrer_policy='strict-origin-when-cross-origin',
)


# Global error handlers - prevent information disclosure
@app.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors without exposing details."""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'An internal error occurred. Please try again later.'}), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Catch-all exception handler to prevent information disclosure."""
    # Log the full error for debugging
    logger.exception(f"Unhandled exception: {error}")
    # Return generic error message to client
    return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500


# Database URL from environment variable (Render provides this for PostgreSQL)
DATABASE_URL = os.environ.get('DATABASE_URL')


def get_db():
    """Get database connection."""
    if DATABASE_URL:
        # PostgreSQL (production)
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL)
        return conn, True  # Return tuple: (connection, is_postgres)
    else:
        # SQLite fallback (local development)
        import sqlite3
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        return conn, False


# Initialize authentication
auth.init_auth(app, get_db, limiter)


@app.after_request
def inject_csrf_token(response):
    """Inject CSRF token into cookies for JavaScript access."""
    response.set_cookie(
        'csrf_token',
        generate_csrf(),
        secure=os.environ.get('FLASK_ENV') == 'production',
        httponly=False,  # Must be False for JS to read it
        samesite='Lax'
    )
    return response


def init_db():
    """Initialize the database with the todos table."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    
    if is_postgres:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS todos (
                id SERIAL PRIMARY KEY,
                text TEXT NOT NULL,
                completed BOOLEAN DEFAULT FALSE,
                deadline TIMESTAMP,
                description TEXT,
                notes TEXT,
                archived BOOLEAN DEFAULT FALSE,
                google_event_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Google tokens table for OAuth credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS google_tokens (
                id SERIAL PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                token_uri TEXT,
                client_id TEXT,
                client_secret TEXT,
                scopes TEXT,
                expiry TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Add new columns if they don't exist (for existing PostgreSQL databases)
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN description TEXT')
        except:
            conn.rollback()
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN notes TEXT')
        except:
            conn.rollback()
        # Migrate deadline from DATE to TIMESTAMP if needed
        try:
            cursor.execute('ALTER TABLE todos ALTER COLUMN deadline TYPE TIMESTAMP USING deadline::timestamp')
        except:
            conn.rollback()
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN archived BOOLEAN DEFAULT FALSE')
        except:
            conn.rollback()
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN google_event_id TEXT')
        except:
            conn.rollback()
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                completed BOOLEAN DEFAULT 0,
                deadline TIMESTAMP,
                description TEXT,
                notes TEXT,
                archived INTEGER DEFAULT 0,
                google_event_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Google tokens table for OAuth credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS google_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                token_uri TEXT,
                client_id TEXT,
                client_secret TEXT,
                scopes TEXT,
                expiry TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Add columns if they don't exist (for existing SQLite databases)
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN deadline TIMESTAMP')
        except:
            pass  # Column already exists
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN description TEXT')
        except:
            pass  # Column already exists
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN notes TEXT')
        except:
            pass  # Column already exists
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN archived INTEGER DEFAULT 0')
        except:
            pass  # Column already exists
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN google_event_id TEXT')
        except:
            pass  # Column already exists
    
    conn.commit()
    
    # Initialize users table and add user_id columns
    auth.init_users_table(conn, is_postgres)
    auth.add_user_id_to_todos(conn, is_postgres)
    auth.add_user_id_to_google_tokens(conn, is_postgres)
    
    conn.close()


@app.route('/')
@login_required
def index():
    """Serve the main page."""
    return render_template('index.html')


def row_to_dict(row, columns):
    """Convert a database row to a dictionary."""
    result = dict(zip(columns, row))
    # Convert date/datetime objects to ISO format strings for consistent JSON serialization
    # PostgreSQL returns datetime.date objects, while SQLite returns strings
    for key in ['deadline', 'created_at']:
        if result.get(key) and hasattr(result[key], 'isoformat'):
            result[key] = result[key].isoformat()
    return result


@app.route('/api/todos', methods=['GET'])
@login_required
def get_todos():
    """Get all to-do items for the current user. Use ?include_archived=true to include archived tasks."""
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
        placeholder = '%s' if is_postgres else '?'
        
        include_archived = request.args.get('include_archived', 'false').lower() == 'true'
        
        if include_archived:
            cursor.execute(
                f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE user_id = {placeholder} ORDER BY created_at DESC',
                (current_user.id,)
            )
        else:
            cursor.execute(
                f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE user_id = {placeholder} AND archived = {placeholder} ORDER BY created_at DESC',
                (current_user.id, False)
            )
        
        todos = [row_to_dict(row, columns) for row in cursor.fetchall()]
    finally:
        conn.close()
    return jsonify(todos)


@app.route('/api/todos', methods=['POST'])
@login_required
def add_todo():
    """Add a new to-do item for the current user."""
    data = request.get_json()
    text = data.get('text', '').strip()
    deadline = data.get('deadline') or None  # Optional deadline (ISO timestamp)
    # Sanitize HTML in description and notes to prevent XSS
    description_raw = data.get('description', '').strip() or None
    description = sanitize_html(description_raw) if description_raw else None
    notes_raw = data.get('notes', '').strip() or None
    notes = sanitize_html(notes_raw) if notes_raw else None
    
    # Validate input
    is_valid, error = validate_todo_input(text=text, description=description_raw, notes=notes_raw, deadline=deadline)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
        
        if is_postgres:
            cursor.execute(
                'INSERT INTO todos (text, deadline, description, notes, user_id) VALUES (%s, %s, %s, %s, %s) RETURNING id, text, completed, deadline, description, notes, archived, created_at',
                (text, deadline, description, notes, current_user.id)
            )
            todo = row_to_dict(cursor.fetchone(), columns)
        else:
            cursor.execute('INSERT INTO todos (text, deadline, description, notes, user_id) VALUES (?, ?, ?, ?, ?)', (text, deadline, description, notes, current_user.id))
            todo_id = cursor.lastrowid
            cursor.execute('SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = ?', (todo_id,))
            todo = row_to_dict(cursor.fetchone(), columns)
        
        conn.commit()
    finally:
        conn.close()
    
    # Sync to Google Calendar if deadline is set (non-critical)
    if deadline:
        try:
            sync_todo_to_calendar(todo['id'], text, deadline, description)
        except Exception as e:
            logger.warning(f"Failed to sync todo to calendar: {e}")
    
    return jsonify(todo), 201


@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
@login_required
def toggle_todo(todo_id):
    """Toggle the completion status of a to-do item."""
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
        placeholder = '%s' if is_postgres else '?'
        
        # Verify todo belongs to current user
        cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = {placeholder} AND user_id = {placeholder}', (todo_id, current_user.id))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Todo not found'}), 404
        
        todo = row_to_dict(row, columns)
        new_status = not todo['completed']
        
        cursor.execute(f'UPDATE todos SET completed = {placeholder} WHERE id = {placeholder} AND user_id = {placeholder}', (new_status, todo_id, current_user.id))
        conn.commit()
        
        cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
        updated_todo = row_to_dict(cursor.fetchone(), columns)
    finally:
        conn.close()
    
    return jsonify(updated_todo)


@app.route('/api/todos/<int:todo_id>', methods=['PATCH'])
@login_required
def update_todo(todo_id):
    """Update a to-do item's details (description, notes, deadline, archived)."""
    data = request.get_json()
    
    # Validate input fields that are provided
    text_to_validate = data.get('text', '').strip() if 'text' in data else None
    description_to_validate = data.get('description', '') if 'description' in data else None
    notes_to_validate = data.get('notes', '') if 'notes' in data else None
    deadline_to_validate = data.get('deadline') if 'deadline' in data else None
    
    is_valid, error = validate_todo_input(
        text=text_to_validate,
        description=description_to_validate,
        notes=notes_to_validate,
        deadline=deadline_to_validate
    )
    if not is_valid:
        return jsonify({'error': error}), 400
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
        placeholder = '%s' if is_postgres else '?'
        
        # Check if todo exists and belongs to current user
        cursor.execute(f'SELECT id FROM todos WHERE id = {placeholder} AND user_id = {placeholder}', (todo_id, current_user.id))
        if not cursor.fetchone():
            return jsonify({'error': 'Todo not found'}), 404
        
        # Build dynamic update query based on provided fields
        update_fields = []
        values = []
        
        if 'description' in data:
            update_fields.append(f'description = {placeholder}')
            # Sanitize HTML in description to prevent XSS
            desc_value = sanitize_html(data['description']) if data['description'] else None
            values.append(desc_value)
        
        if 'notes' in data:
            update_fields.append(f'notes = {placeholder}')
            # Sanitize HTML in notes to prevent XSS
            notes_value = sanitize_html(data['notes']) if data['notes'] else None
            values.append(notes_value)
        
        if 'deadline' in data:
            update_fields.append(f'deadline = {placeholder}')
            values.append(data['deadline'] or None)
        
        if 'text' in data:
            update_fields.append(f'text = {placeholder}')
            values.append(data['text'].strip())
        
        if 'archived' in data:
            update_fields.append(f'archived = {placeholder}')
            values.append(bool(data['archived']))
        
        if not update_fields:
            return jsonify({'error': 'No fields to update'}), 400
        
        values.append(todo_id)
        query = f"UPDATE todos SET {', '.join(update_fields)} WHERE id = {placeholder}"
        cursor.execute(query, tuple(values))
        conn.commit()
        
        cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
        updated_todo = row_to_dict(cursor.fetchone(), columns)
    finally:
        conn.close()
    
    # Sync to Google Calendar if deadline, text, or description changed (non-critical)
    if 'deadline' in data or 'text' in data or 'description' in data:
        try:
            new_deadline = updated_todo.get('deadline')
            if new_deadline:
                sync_todo_to_calendar(
                    todo_id,
                    updated_todo['text'],
                    new_deadline,
                    updated_todo.get('description')
                )
            elif 'deadline' in data and data['deadline'] is None:
                # Deadline was removed, delete the calendar event
                delete_todo_calendar_event(todo_id)
        except Exception as e:
            logger.warning(f"Failed to sync todo to calendar: {e}")
    
    return jsonify(updated_todo)


@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
@login_required
def delete_todo(todo_id):
    """Delete a to-do item."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    placeholder = '%s' if is_postgres else '?'
    
    try:
        # Verify todo belongs to current user and get google_event_id in same query
        cursor.execute(
            f'SELECT id, google_event_id FROM todos WHERE id = {placeholder} AND user_id = {placeholder}',
            (todo_id, current_user.id)
        )
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Todo not found'}), 404
        
        google_event_id = row[1]
        
        # Delete from database first
        cursor.execute(
            f'DELETE FROM todos WHERE id = {placeholder} AND user_id = {placeholder}',
            (todo_id, current_user.id)
        )
        conn.commit()
    finally:
        conn.close()
    
    # Delete associated Google Calendar event after DB connection is closed
    # This prevents nested connection issues in PostgreSQL
    if google_event_id:
        try:
            credentials = get_google_credentials()
            if credentials:
                gcal.delete_calendar_event(credentials, google_event_id)
        except Exception as e:
            # Calendar deletion is non-critical; log and continue
            logger.warning(f"Failed to delete calendar event {google_event_id}: {e}")
    
    return jsonify({'success': True})


# ============================================================================
# Google Calendar OAuth Endpoints
# ============================================================================

def get_google_tokens(user_id=None):
    """Get stored Google OAuth tokens from database for a specific user."""
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    if user_id is None:
        return None
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        cursor.execute(
            f'SELECT access_token, refresh_token, token_uri, client_id, client_secret, scopes, expiry FROM google_tokens WHERE user_id = {placeholder} ORDER BY id DESC LIMIT 1',
            (user_id,)
        )
        row = cursor.fetchone()
    finally:
        conn.close()
    
    if not row:
        return None
    
    columns = ['access_token', 'refresh_token', 'token_uri', 'client_id', 'client_secret', 'scopes', 'expiry']
    token_data = dict(zip(columns, row))
    
    # Convert expiry to string if it's a datetime object
    if token_data.get('expiry') and hasattr(token_data['expiry'], 'isoformat'):
        token_data['expiry'] = token_data['expiry'].isoformat()
    
    # Decrypt sensitive token fields
    return crypto_utils.decrypt_token_data(token_data)


def save_google_tokens(token_data, user_id=None):
    """Save Google OAuth tokens to database for a specific user."""
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    if user_id is None:
        return
    
    # Encrypt sensitive token fields before storing
    encrypted_data = crypto_utils.encrypt_token_data(token_data)
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        
        # Clear existing tokens for this user
        cursor.execute(f'DELETE FROM google_tokens WHERE user_id = {placeholder}', (user_id,))
        
        # Insert new encrypted tokens
        cursor.execute(f'''
            INSERT INTO google_tokens (access_token, refresh_token, token_uri, client_id, client_secret, scopes, expiry, user_id)
            VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
        ''', (
            encrypted_data['access_token'],
            encrypted_data.get('refresh_token'),
            encrypted_data.get('token_uri'),
            encrypted_data.get('client_id'),
            encrypted_data.get('client_secret'),
            encrypted_data.get('scopes'),
            encrypted_data.get('expiry'),
            user_id
        ))
        
        conn.commit()
    finally:
        conn.close()


def delete_google_tokens(user_id=None):
    """Delete stored Google OAuth tokens for a specific user."""
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    if user_id is None:
        return
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        cursor.execute(f'DELETE FROM google_tokens WHERE user_id = {placeholder}', (user_id,))
        conn.commit()
    finally:
        conn.close()


def get_google_credentials(user_id=None):
    """Get Google credentials object from stored tokens for a specific user."""
    token_data = get_google_tokens(user_id)
    if not token_data:
        return None
    
    try:
        return gcal.build_credentials_from_tokens(token_data)
    except Exception as e:
        logger.error(f"Error building credentials: {e}")
        return None


@app.route('/api/google/status', methods=['GET'])
@login_required
def google_status():
    """Check Google Calendar connection status for current user."""
    if not gcal.is_configured():
        return jsonify({
            'configured': False,
            'connected': False,
            'message': 'Google Calendar integration not configured'
        })
    
    tokens = get_google_tokens()
    connected = tokens is not None and tokens.get('access_token') is not None
    
    return jsonify({
        'configured': True,
        'connected': connected
    })


@app.route('/api/google/auth', methods=['GET'])
@login_required
def google_auth():
    """Initiate Google OAuth flow."""
    if not gcal.is_configured():
        return jsonify({'error': 'Google Calendar integration not configured'}), 400
    
    try:
        authorization_url, state = gcal.get_authorization_url()
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"OAuth auth error: {e}")
        return jsonify({'error': 'Failed to initiate authentication'}), 500


@app.route('/api/google/callback', methods=['GET'])
@login_required
def google_callback():
    """Handle Google OAuth callback."""
    error = request.args.get('error')
    if error:
        logger.warning(f"OAuth callback error: {error}")
        error_description = request.args.get('error_description', '')
        if error == 'access_denied':
            flash('Google Calendar connection was cancelled.', 'info')
        else:
            flash('Failed to connect to Google Calendar. Please try again.', 'error')
        return redirect('/')
    
    code = request.args.get('code')
    if not code:
        logger.warning("OAuth callback missing code")
        flash('Google Calendar connection failed. Please try again.', 'error')
        return redirect('/')
    
    # Validate OAuth state to prevent CSRF attacks
    stored_state = session.get('oauth_state')
    received_state = request.args.get('state')
    
    if not stored_state or stored_state != received_state:
        logger.warning(f"OAuth state mismatch: stored={stored_state}, received={received_state}")
        session.pop('oauth_state', None)  # Clear the invalid state
        flash('Authentication session expired. Please try again.', 'error')
        return redirect('/')
    
    try:
        token_data = gcal.exchange_code_for_tokens(code, stored_state)
        save_google_tokens(token_data)
        session.pop('oauth_state', None)  # Clear state after successful use
        flash('Successfully connected to Google Calendar!', 'success')
        return redirect('/')
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        session.pop('oauth_state', None)
        flash('Failed to complete Google Calendar connection. Please try again.', 'error')
        return redirect('/')


@app.route('/api/google/disconnect', methods=['POST'])
@login_required
def google_disconnect():
    """Disconnect Google Calendar (revoke and delete tokens)."""
    credentials = get_google_credentials()
    
    if credentials:
        gcal.revoke_credentials(credentials)
    
    delete_google_tokens()
    
    return jsonify({'success': True})


# ============================================================================
# Google Calendar Sync Helpers
# ============================================================================

def sync_todo_to_calendar(todo_id, text, deadline, description=None):
    """Create or update a calendar event for a todo."""
    if not deadline:
        return None
    
    credentials = get_google_credentials()
    if not credentials:
        return None
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        
        # Check if todo already has a calendar event
        cursor.execute(f'SELECT google_event_id FROM todos WHERE id = {placeholder}', (todo_id,))
        row = cursor.fetchone()
    finally:
        conn.close()
    
    if not row:
        return None
    
    existing_event_id = row[0]
    
    if existing_event_id:
        # Update existing event
        success = gcal.update_calendar_event(
            credentials,
            existing_event_id,
            title=text,
            start_datetime=deadline,
            description=description
        )
        return existing_event_id if success else None
    else:
        # Create new event
        event_id = gcal.create_calendar_event(
            credentials,
            title=text,
            start_datetime=deadline,
            description=description
        )
        
        if event_id:
            # Store event ID in database
            conn, is_postgres = get_db()
            try:
                cursor = conn.cursor()
                placeholder = '%s' if is_postgres else '?'
                cursor.execute(f'UPDATE todos SET google_event_id = {placeholder} WHERE id = {placeholder}', (event_id, todo_id))
                conn.commit()
            finally:
                conn.close()
        
        return event_id


def delete_todo_calendar_event(todo_id):
    """Delete the calendar event associated with a todo."""
    credentials = get_google_credentials()
    if not credentials:
        return False
    
    conn, is_postgres = get_db()
    try:
        cursor = conn.cursor()
        placeholder = '%s' if is_postgres else '?'
        
        cursor.execute(f'SELECT google_event_id FROM todos WHERE id = {placeholder}', (todo_id,))
        row = cursor.fetchone()
    finally:
        conn.close()
    
    if not row or not row[0]:
        return False
    
    event_id = row[0]
    return gcal.delete_calendar_event(credentials, event_id)


# Initialize database on module load (needed for gunicorn)
init_db()

if __name__ == '__main__':
    # Local development only
    app.run(debug=True)
