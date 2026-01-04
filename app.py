"""
Simple To-Do List Application
Flask backend with PostgreSQL database
"""

import os
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

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
    
    conn.commit()
    conn.close()


@app.route('/')
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
def get_todos():
    """Get all to-do items. Use ?include_archived=true to include archived tasks."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
    
    include_archived = request.args.get('include_archived', 'false').lower() == 'true'
    
    if include_archived:
        cursor.execute('SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos ORDER BY created_at DESC')
    else:
        placeholder = '%s' if is_postgres else '?'
        cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE archived = {placeholder} ORDER BY created_at DESC', (False,))
    
    todos = [row_to_dict(row, columns) for row in cursor.fetchall()]
    conn.close()
    return jsonify(todos)


@app.route('/api/todos', methods=['POST'])
def add_todo():
    """Add a new to-do item."""
    data = request.get_json()
    text = data.get('text', '').strip()
    deadline = data.get('deadline') or None  # Optional deadline (ISO timestamp)
    description = data.get('description', '').strip() or None
    notes = data.get('notes', '').strip() or None
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
    
    if is_postgres:
        cursor.execute(
            'INSERT INTO todos (text, deadline, description, notes) VALUES (%s, %s, %s, %s) RETURNING id, text, completed, deadline, description, notes, archived, created_at',
            (text, deadline, description, notes)
        )
        todo = row_to_dict(cursor.fetchone(), columns)
    else:
        cursor.execute('INSERT INTO todos (text, deadline, description, notes) VALUES (?, ?, ?, ?)', (text, deadline, description, notes))
        todo_id = cursor.lastrowid
        cursor.execute('SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = ?', (todo_id,))
        todo = row_to_dict(cursor.fetchone(), columns)
    
    conn.commit()
    conn.close()
    
    return jsonify(todo), 201


@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
def toggle_todo(todo_id):
    """Toggle the completion status of a to-do item."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
    placeholder = '%s' if is_postgres else '?'
    
    cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Todo not found'}), 404
    
    todo = row_to_dict(row, columns)
    new_status = not todo['completed']
    
    cursor.execute(f'UPDATE todos SET completed = {placeholder} WHERE id = {placeholder}', (new_status, todo_id))
    conn.commit()
    
    cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
    updated_todo = row_to_dict(cursor.fetchone(), columns)
    conn.close()
    
    return jsonify(updated_todo)


@app.route('/api/todos/<int:todo_id>', methods=['PATCH'])
def update_todo(todo_id):
    """Update a to-do item's details (description, notes, deadline, archived)."""
    data = request.get_json()
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    columns = ['id', 'text', 'completed', 'deadline', 'description', 'notes', 'archived', 'created_at']
    placeholder = '%s' if is_postgres else '?'
    
    # Check if todo exists
    cursor.execute(f'SELECT id FROM todos WHERE id = {placeholder}', (todo_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Todo not found'}), 404
    
    # Build dynamic update query based on provided fields
    update_fields = []
    values = []
    
    if 'description' in data:
        update_fields.append(f'description = {placeholder}')
        values.append(data['description'] or None)
    
    if 'notes' in data:
        update_fields.append(f'notes = {placeholder}')
        values.append(data['notes'] or None)
    
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
        conn.close()
        return jsonify({'error': 'No fields to update'}), 400
    
    values.append(todo_id)
    query = f"UPDATE todos SET {', '.join(update_fields)} WHERE id = {placeholder}"
    cursor.execute(query, tuple(values))
    conn.commit()
    
    cursor.execute(f'SELECT id, text, completed, deadline, description, notes, archived, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
    updated_todo = row_to_dict(cursor.fetchone(), columns)
    conn.close()
    
    return jsonify(updated_todo)


@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
def delete_todo(todo_id):
    """Delete a to-do item."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    placeholder = '%s' if is_postgres else '?'
    
    cursor.execute(f'SELECT id FROM todos WHERE id = {placeholder}', (todo_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Todo not found'}), 404
    
    cursor.execute(f'DELETE FROM todos WHERE id = {placeholder}', (todo_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


# Initialize database on module load (needed for gunicorn)
init_db()

if __name__ == '__main__':
    # Local development only
    app.run(debug=True)
