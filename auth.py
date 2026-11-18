import sqlite3
import os
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

class User(UserMixin):
    def __init__(self, id, username):
        self.id = str(id)
        self.username = username

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return User(id=row[0], username=row[1])
        return None

    @staticmethod
    def authenticate(username, password):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row and check_password_hash(row[2], password):
            return User(id=row[0], username=row[1])
        return None

    @staticmethod
    def register(username, password):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            pw_hash = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
