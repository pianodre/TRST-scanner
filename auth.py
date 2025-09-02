"""
Authentication module for user management and verification.
"""

import sqlite3
import bcrypt
from functools import wraps
from flask import session, jsonify, request, render_template, redirect, url_for, flash


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect('scanner.db')
    conn.row_factory = sqlite3.Row
    return conn


def verify_user(username, password):
    """Verify user credentials against database."""
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return True
    return False


def require_login(f):
    """Decorator to require login for API routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def login_route():
    """Handle login page and authentication."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if verify_user(username, password):
            session['username'] = username
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')


def logout_route():
    """Handle user logout."""
    username = session.get('username', 'User')
    session.pop('username', None)
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('login'))


def home_route():
    """Handle home page with authentication check."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])
