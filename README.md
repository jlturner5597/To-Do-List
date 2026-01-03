# To-Do List Application

A simple to-do list app built with Flask and SQLite.

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python app.py
   ```

3. Open http://localhost:5000 in your browser

## Project Structure

```
To-Do List/
├── app.py              # Flask application (main file)
├── database.db         # SQLite database (auto-created on first run)
├── requirements.txt    # Python dependencies
├── static/
│   └── style.css       # Styling
└── templates/
    └── index.html      # HTML template
```

## Features

- Add new to-do items
- Set optional deadlines via date picker
- Click checkbox to mark as complete/incomplete
- Delete items with the × button
- Overdue items highlighted in red
- Tasks persist in SQLite database
