# Simple Flask App

A barebones Flask backend with HTML frontend.

## Project Structure
```
/
├── app.py              # Flask backend
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
│   └── index.html     # Main page
└── static/            # Static files
    ├── style.css      # CSS styles
    └── script.js      # JavaScript
```

## Setup
1. Create virtual environment: `python3 -m venv venv`
2. Activate virtual environment: `source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the app: `python app.py`
5. Visit: http://localhost:8000

## Running the App (after initial setup)
1. **Activate virtual environment:** `source venv/bin/activate`
2. **Run Flask app:** `python app.py`
3. **Open browser:** Visit `http://localhost:8000`

**One-liner:** `source venv/bin/activate && python app.py`

**Note:** You'll see `(venv)` in your terminal when the virtual environment is active.

## Features
- Flask backend on port 8000
- Simple API endpoint at `/api/hello`
- Interactive frontend with API testing
# TRST-scanner
