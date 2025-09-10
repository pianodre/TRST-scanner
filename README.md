# Domain & Email Security Scanner

A comprehensive security scanning application that analyzes domains and email addresses for potential security risks, breaches, and vulnerabilities. Built with Flask backend, SQLite database, and modern web frontend with secure authentication.

## Features

- **Secure Authentication** - Login system with bcrypt password hashing
- **Domain Analysis** - WHOIS data, DNS records, DMARC policy analysis
- **Email Security** - Breach detection via LeakCheck, validation, and security protocols
- **Risk Assessment** - Combined security scoring and threat analysis
- **Modern UI** - Responsive design with dark theme and interactive results

## Project Structure
```
/
├── app.py                      # Flask routes and main application
├── init_db.py                  # Database initialization script
├── scanner.db                  # SQLite database (auto-generated)
├── requirements.txt            # Python dependencies
├── services/                   # Business logic modules
│   ├── __init__.py            # Package initialization
│   ├── domain_services.py     # WHOIS & domain analysis
│   ├── email_services.py      # Email breach detection (LeakCheck)
│   └── security_utils.py      # Risk assessment utilities
├── templates/                  # HTML templates
│   ├── index.html             # Main scanner interface
│   └── login.html             # Authentication page
├── static/                    # Static assets
│   ├── style.css             # Application styles
│   └── script.js             # Frontend JavaScript
└── images/                    # Logo and image assets
```

## Setup

### Initial Setup
1. **Clone/Download** the project
2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   ```
3. **Activate virtual environment:**
   ```bash
   source venv/bin/activate
   ```
4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
5. **Initialize database:**
   ```bash
   python init_db.py
   ```
6. **Start the application:**
   ```bash
   python app.py
   ```
7. **Open browser:** Visit `http://localhost:8000`

### Daily Usage
```bash
# One-liner to start the app
source venv/bin/activate && python app.py
```

**Note:** You'll see `(venv)` in your terminal when the virtual environment is active.

## Login Credentials

- **Admin:** `admin` / `admin`
- **Guest:** `guest` / `guest`

## Security Features

- **Password Hashing** - All passwords stored with bcrypt + salt
- **Session Management** - Secure Flask sessions with secret key
- **Database Storage** - SQLite with proper schema design
- **Protected Routes** - Authentication required for all scanner APIs
- **Environment Variables** - Support for production secret key override

## API Endpoints

All endpoints require authentication:

- `GET /` - Main scanner interface
- `GET /login` - Authentication page
- `GET /logout` - End session
- `POST /api/whois/scan` - Domain WHOIS analysis
- `POST /api/dmarc/scan` - DMARC policy analysis
- `POST /api/leakcheck/scan` - Email breach detection
- `POST /api/scan/combined` - Comprehensive analysis

## Development

### Environment Variables
```bash
export SECRET_KEY="your-production-secret-key"
```

### Database Management
```bash
# Reinitialize database (WARNING: Deletes existing data)
rm scanner.db && python init_db.py
```

### Adding Users
Modify `init_db.py` and run the initialization script, or extend the application with user management features.

## Production Deployment

1. Set secure `SECRET_KEY` environment variable
2. Use production WSGI server (gunicorn, uWSGI)
3. Configure proper database backup strategy
4. Enable HTTPS and secure headers
5. Consider rate limiting and monitoring
