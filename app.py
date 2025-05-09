import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, login_user, login_required, UserMixin, current_user
import random
import json
from datetime import datetime

# Database setup
db = SQL("sqlite:///logins.db")

# Configure application
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User class for Flask-Login
class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if user:
        user_obj = User()
        user_obj.id = user[0]['id']
        user_obj.username = user[0]['username']  # Add username attribute
        user_obj.emoji = user[0]['emoji']  # Add emoji attribute
        return user_obj
    return None

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        emoji = request.form.get('emoji')  # New emoji field

        if not username or not password:
            return render_template("error.html", message="Please fill in all fields.")

        if password != confirmation:
            return render_template("error.html", message="Passwords do not match.")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return render_template("error.html", message="Username already taken.")

        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash, emoji) VALUES (?, ?, ?)", username, hashed_password, emoji)

        user = User()
        user.id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
        user.username = username
        user.emoji = emoji  # Set emoji for user
        login_user(user)

        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("error.html", message="Must provide username")
        if not request.form.get("password"):
            return render_template("error.html", message="Must provide password")

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html", message="Invalid username or password")

        user = User()
        user.id = rows[0]["id"]
        user.username = rows[0]["username"]
        user.emoji = rows[0]["emoji"]  # Load emoji
        login_user(user)

        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("index.html")
    else:
        return render_template("home1.html")

@app.route("/generate", methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        while True:
            h = random.randint(1000, 10000000)
            existing_chat = db.execute("SELECT * FROM group_chats WHERE id = ?", h)
            if not existing_chat:
                break

        db.execute("INSERT INTO group_chats (id) VALUES (?)", h)

        return render_template("generate.html", key=h)
    else:
        return render_template("generate.html")

@app.route("/messages/<key>")
@login_required
def get_messages(key):
    try:
        with open("messages.json", "r") as file:
            data = json.load(file)
    
        return jsonify({"messages": data.get(key, [])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/chat_room/<key>", methods=['POST'])
@login_required
def post_message(key):
    message = request.json.get('message')

    # Check if the message is provided
    if not message:
        return jsonify({"error": "Message cannot be empty."}), 400

    try:
        # Load existing messages
        with open("messages.json", "r") as file:
            data = json.load(file)

        # Check if the key exists in the chat data
        if key not in data:
            data[key] = []  # Create an entry for this key if it doesn't exist

        # Append new message with a timestamp including seconds
        data[key].append({
            "username": current_user.username,
            "emoji": current_user.emoji,
            "message": message,
            "timestamp": datetime.now().strftime("%A, %d %B %Y, %I:%M:%S %p")
        })

        # Save updated messages
        with open("messages.json", "w") as file:
            json.dump(data, file)

        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"Error posting message: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    # Delete the user's account from the database
    db.execute("DELETE FROM users WHERE id = ?", current_user.id)

    # Log the user out and redirect to the home page or login page
    logout()
    flash("Your account has been deleted.")
    return redirect("/")

@app.route("/chat", methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == "POST":
        key = request.form.get("key")

        chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", key)
        if len(chat_group) == 0:
            return render_template("chat.html", error="Invalid key. Please try again.")

        return render_template("chat_room.html", key=key)

    return render_template("chat.html")

@app.route("/delete_chat/<key>", methods=["POST"])
@login_required
def delete_chat(key):
    db.execute("DELETE FROM group_chats WHERE id = ?", key)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
