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
                deadline DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                completed BOOLEAN DEFAULT 0,
                deadline DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Add deadline column if it doesn't exist (for existing SQLite databases)
        try:
            cursor.execute('ALTER TABLE todos ADD COLUMN deadline DATE')
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
    return dict(zip(columns, row))


@app.route('/api/todos', methods=['GET'])
def get_todos():
    """Get all to-do items."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, text, completed, deadline, created_at FROM todos ORDER BY created_at DESC')
    columns = ['id', 'text', 'completed', 'deadline', 'created_at']
    todos = [row_to_dict(row, columns) for row in cursor.fetchall()]
    conn.close()
    return jsonify(todos)


@app.route('/api/todos', methods=['POST'])
def add_todo():
    """Add a new to-do item."""
    data = request.get_json()
    text = data.get('text', '').strip()
    deadline = data.get('deadline') or None  # Optional deadline
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    columns = ['id', 'text', 'completed', 'deadline', 'created_at']
    
    if is_postgres:
        cursor.execute(
            'INSERT INTO todos (text, deadline) VALUES (%s, %s) RETURNING id, text, completed, deadline, created_at',
            (text, deadline)
        )
        todo = row_to_dict(cursor.fetchone(), columns)
    else:
        cursor.execute('INSERT INTO todos (text, deadline) VALUES (?, ?)', (text, deadline))
        todo_id = cursor.lastrowid
        cursor.execute('SELECT id, text, completed, deadline, created_at FROM todos WHERE id = ?', (todo_id,))
        todo = row_to_dict(cursor.fetchone(), columns)
    
    conn.commit()
    conn.close()
    
    return jsonify(todo), 201


@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
def toggle_todo(todo_id):
    """Toggle the completion status of a to-do item."""
    conn, is_postgres = get_db()
    cursor = conn.cursor()
    columns = ['id', 'text', 'completed', 'deadline', 'created_at']
    placeholder = '%s' if is_postgres else '?'
    
    cursor.execute(f'SELECT id, text, completed, deadline, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Todo not found'}), 404
    
    todo = row_to_dict(row, columns)
    new_status = not todo['completed']
    
    cursor.execute(f'UPDATE todos SET completed = {placeholder} WHERE id = {placeholder}', (new_status, todo_id))
    conn.commit()
    
    cursor.execute(f'SELECT id, text, completed, deadline, created_at FROM todos WHERE id = {placeholder}', (todo_id,))
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
