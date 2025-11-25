from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import sqlite3
import bcrypt

app = Flask(__name__)
CORS(app)  # allow frontend JS to call backend APIs

@app.route("/")
def index():
    return render_template("index.html")

# --- Database setup ---
def init_db():
    connection = sqlite3.connect('data.db')
    c = connection.cursor()
    # Create users table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    connection.commit()
    connection.close()

init_db()

# --- Signup API ---
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return "Missing username or password", 400

    # Hash the password before storing
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_pw_str = hashed_pw.decode('utf-8')  # store as TEXT

    try:
        connection = sqlite3.connect("data.db")
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw_str))
        connection.commit()
        connection.close()
        return "User Signup Successfully", 201
    except sqlite3.IntegrityError:
        return "Username already exists", 409
    except Exception as e:
        return str(e), 500

# --- Login API ---
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return "Missing username or password", 400

    try:
        connection = sqlite3.connect("data.db")
        cursor = connection.cursor()
        # Only select the password column
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        connection.close()

        if row:
            stored_hash_str = row[0]  # password hash string from DB
            stored_hash_bytes = stored_hash_str.encode('utf-8')  # convert back to bytes
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash_bytes):
                return "Login successful", 200
            else:
                return "Invalid username or password", 401
        else:
            return "Invalid username or password", 401
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(debug=True, port=3000)
