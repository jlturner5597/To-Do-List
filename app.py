"""
Simple To-Do List Application
Flask backend with SQLite database
"""

import os
from flask import Flask, render_template, request, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Use environment variable for database path, with fallback for local development
DATABASE = os.environ.get('DATABASE_PATH', 'database.db')


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with the todos table."""
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            completed BOOLEAN DEFAULT 0,
            deadline DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add deadline column if it doesn't exist (for existing databases)
    try:
        conn.execute('ALTER TABLE todos ADD COLUMN deadline DATE')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    conn.commit()
    conn.close()


@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/api/todos', methods=['GET'])
def get_todos():
    """Get all to-do items."""
    conn = get_db()
    todos = conn.execute('SELECT * FROM todos ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(todo) for todo in todos])


@app.route('/api/todos', methods=['POST'])
def add_todo():
    """Add a new to-do item."""
    data = request.get_json()
    text = data.get('text', '').strip()
    deadline = data.get('deadline') or None  # Optional deadline
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO todos (text, deadline) VALUES (?, ?)',
        (text, deadline)
    )
    todo_id = cursor.lastrowid
    conn.commit()
    
    todo = conn.execute('SELECT * FROM todos WHERE id = ?', (todo_id,)).fetchone()
    conn.close()
    
    return jsonify(dict(todo)), 201


@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
def toggle_todo(todo_id):
    """Toggle the completion status of a to-do item."""
    conn = get_db()
    
    todo = conn.execute('SELECT * FROM todos WHERE id = ?', (todo_id,)).fetchone()
    if not todo:
        conn.close()
        return jsonify({'error': 'Todo not found'}), 404
    
    new_status = not todo['completed']
    conn.execute('UPDATE todos SET completed = ? WHERE id = ?', (new_status, todo_id))
    conn.commit()
    
    updated_todo = conn.execute('SELECT * FROM todos WHERE id = ?', (todo_id,)).fetchone()
    conn.close()
    
    return jsonify(dict(updated_todo))


@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
def delete_todo(todo_id):
    """Delete a to-do item."""
    conn = get_db()
    
    todo = conn.execute('SELECT * FROM todos WHERE id = ?', (todo_id,)).fetchone()
    if not todo:
        conn.close()
        return jsonify({'error': 'Todo not found'}), 404
    
    conn.execute('DELETE FROM todos WHERE id = ?', (todo_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


# Initialize database on module load (needed for gunicorn)
init_db()

if __name__ == '__main__':
    # Local development only
    app.run(debug=True)
