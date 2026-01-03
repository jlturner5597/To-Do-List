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

## Deployment to Render

1. Push this repository to GitHub
2. Go to [render.com](https://render.com) and sign up/log in
3. Click **New** → **Blueprint**
4. Connect your GitHub account and select this repository
5. Render will detect `render.yaml` and configure automatically
6. Click **Apply** to deploy

Your app will be live at `https://todo-list-xxxx.onrender.com`

> **Note:** The free tier spins down after inactivity. First request after idle may take ~30 seconds.
