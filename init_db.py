#!/usr/bin/env python3
"""
Database initialization script for the scanner application.
Creates SQLite database with users table and default admin/guest accounts.
"""

import sqlite3
import bcrypt
import os

def init_database():
    """Initialize the SQLite database with users table and default accounts."""
    
    # Create database connection
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Hash passwords for default users
    admin_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
    guest_password = bcrypt.hashpw('guest'.encode('utf-8'), bcrypt.gensalt())
    
    # Insert default users (ignore if they already exist)
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash, role) 
            VALUES (?, ?, ?)
        ''', ('admin', admin_password.decode('utf-8'), 'admin'))
        print("✓ Created admin user")
    except sqlite3.IntegrityError:
        print("• Admin user already exists")
    
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash, role) 
            VALUES (?, ?, ?)
        ''', ('guest', guest_password.decode('utf-8'), 'guest'))
        print("✓ Created guest user")
    except sqlite3.IntegrityError:
        print("• Guest user already exists")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print("✓ Database initialization complete!")
    print("📁 Database file: scanner.db")

if __name__ == '__main__':
    print("🔧 Initializing scanner database...")
    init_database()
