# To-Do List Application

A full-stack to-do list web application built as a technical demonstration for the Sales Engineer interview process.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python, Flask |
| **Database** | PostgreSQL (production), SQLite (local dev) |
| **Authentication** | Flask-Login, Werkzeug password hashing |
| **Security** | Flask-Talisman, Flask-Limiter, CSRF protection, XSS sanitization |
| **Integration** | Google Calendar API (OAuth 2.0) |
| **Deployment** | Render.com, Gunicorn |

---

## Features

- **User Authentication** — Register, login, and secure session management
- **Task Management** — Create, edit, complete, archive, and delete tasks
- **Rich Text Notes** — Quill.js editor for detailed task descriptions
- **Deadlines** — Date/time picker with overdue highlighting
- **Google Calendar Sync** — OAuth integration to sync tasks as calendar events
- **Security** — Rate limiting, secure headers, encrypted token storage

---

## Quick Start (Local Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py

# Open http://localhost:5000
```

---

## Project Structure

```
├── app.py              # Main Flask application
├── auth.py             # User authentication module
├── crypto_utils.py     # Token encryption utilities
├── google_calendar.py  # Google Calendar API integration
├── requirements.txt    # Python dependencies
├── render.yaml         # Render deployment configuration
├── static/
│   └── style.css       # Styling
└── templates/
    ├── index.html      # Main application UI
    ├── login.html      # Login page
    └── register.html   # Registration page
```

---

## Deployment

This application is configured for one-click deployment on [Render.com](https://render.com) using the included `render.yaml` Blueprint.

> **Note:** Free tier instances spin down after inactivity; first request may take ~30 seconds to wake.
