import os
import threading
import random
import json
from datetime import datetime, timedelta
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for, send_from_directory
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, login_user, login_required, UserMixin, current_user
from werkzeug.utils import secure_filename
import shutil as shutil
from urllib.parse import unquote
from flask import jsonify, request, redirect, url_for, flash, render_template
import pickle
from PIL import Image

SETTINGS_DIR = "settings"
os.makedirs(SETTINGS_DIR, exist_ok=True)
os.makedirs(os.path.join("static", "profile_pics"), exist_ok=True)
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
        user_obj.username = user[0]['username']
        user_obj.emoji = user[0]['emoji']
        return user_obj
    return None

@app.context_processor
def inject_settings():
    if current_user.is_authenticated:
        user_settings = load_user_settings(current_user.id)
        return dict(settings=user_settings)
    return dict(settings=None)

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
        emoji = request.form.get('emoji')

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
        user.emoji = emoji
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
        user.emoji = rows[0]["emoji"]
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
import re
def extract_mentions(text):
    """Extract @mentions from a message string."""
    # Matches @username or @everyone, usernames must be word chars or underscores
    return set(re.findall(r'@(\w+|everyone)', text or ""))

@app.route("/chat_room/<key>", methods=['POST'])
@login_required
def post_message(key):
    import uuid
    message = request.json.get('message', '')
    image_url = request.json.get('image_url', None)
    reply_to = request.json.get('reply_to', None)

    if not message and not image_url:
        return jsonify({"error": "Message cannot be empty."}), 400

    try:
        with open("messages.json", "r") as file:
            data = json.load(file)

        if key not in data:
            data[key] = []

        user_settings = load_user_settings(current_user.id)
        profile_pic = user_settings.get("profile_pic") or "default.png"
        msg_id = str(uuid.uuid4())

        # Detect mentions
        mentions = extract_mentions(message)
        mentioned_users = []
        highlight = False

        if "everyone" in mentions:
            highlight = True
            mentioned_users = [user['username'] for user in db.execute("SELECT username FROM users")]
        else:
            for username in mentions:
                if username == current_user.username:
                    continue
                rows = db.execute("SELECT * FROM users WHERE username = ?", username)
                if rows:
                    mentioned_users.append(username)
                    highlight = True

        msg_data = {
            "id": msg_id,
            "username": current_user.username,
            "emoji": current_user.emoji,
            "timestamp": datetime.now().isoformat() + "Z",
            "profile_pic": profile_pic,
            "highlight": highlight,  # <<--- THIS IS USED IN THE FRONTEND
            "mentions": mentioned_users,
        }
        if message:
            msg_data["message"] = message
        if image_url:
            msg_data["image_url"] = image_url
        if reply_to:
            msg_data["reply_to"] = reply_to

        data[key].append(msg_data)

        with open("messages.json", "w") as file:
            json.dump(data, file)

        # Optionally: Trigger notifications here
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"Error posting message: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    db.execute("DELETE FROM users WHERE id = ?", current_user.id)
    logout()
    flash("Your account has been deleted.")
    return redirect("/")

@app.route("/chat", methods=['GET', 'POST'])
@login_required
def chat():
    timeout_until = timeouts.get(current_user.username)

    if timeout_until and datetime.now() < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return render_template("timeout.html", timeout_until=timeout_until)

    if request.method == "POST":
        key = request.form.get("key")
        chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", key)
        if len(chat_group) == 0:
            return render_template("chat.html", error="Invalid key. Please try again.")

        return render_template("chat_room.html", key=key)

    return render_template("chat.html")

@app.route("/delete_chat/<chat_id>", methods=["POST"])
@login_required
def delete_chat(chat_id):
    if current_user.username != "h":
        flash("Access denied: Admin privileges required.")
        return redirect("/admin")

    db.execute("DELETE FROM group_chats WHERE id = ?", chat_id)
    flash(f"Group chat '{chat_id}' has been deleted.")
    return redirect("/admin")

@app.route("/admin")
@login_required
def admin():
    if current_user.username != "h":
        flash("Access denied: Admin privileges required.")
        return redirect("/")
    users = db.execute("SELECT username, hash FROM users")
    group_chats = db.execute("SELECT id FROM group_chats")
    images_base = os.path.join(os.getcwd(), "IMAGES")
    image_folders = {}
    if os.path.isdir(images_base):
        for key in os.listdir(images_base):
            folder_path = os.path.join(images_base, key)
            if os.path.isdir(folder_path):
                files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
                image_folders[key] = files
    return render_template("admin.html",
                           users=users,
                           group_chats=group_chats,
                           image_folders=image_folders)

@app.route('/delete_images_folder/<key>', methods=['POST'])
@login_required
def delete_images_folder(key):
    if current_user.username != "h":
        flash("Access denied: Admin privileges required.")
        return redirect("/")
    images_base = os.path.join(os.getcwd(), "IMAGES")
    target = os.path.join(images_base, key)
    if os.path.isdir(target):
        shutil.rmtree(target)
        flash(f"Deleted folder /IMAGES/{key}")
    return redirect(url_for('admin'))

@app.route('/delete_images_folders', methods=['POST'])
@login_required
def delete_images_folders():
    if current_user.username != "h":
        return jsonify(success=False, error="Access denied"), 403
    data = request.get_json()
    keys = data.get('keys', [])
    images_base = os.path.join(os.getcwd(), "IMAGES")
    for key in keys:
        folder = os.path.join(images_base, key)
        if os.path.isdir(folder):
            shutil.rmtree(folder)
    return jsonify(success=True)

@app.route('/delete_image/<key>/<path:filename>', methods=['POST'])
@login_required
def delete_image(key, filename):
    if current_user.username != "h":
        flash("Access denied: Admin privileges required.")
        return redirect("/")
    images_base = os.path.join(os.getcwd(), "IMAGES")
    decoded_filename = unquote(filename)
    file_path = os.path.join(images_base, key, decoded_filename)
    if os.path.isfile(file_path):
        os.remove(file_path)
        flash(f"Deleted image {decoded_filename} from folder {key}")
    return redirect(url_for('admin'))

@app.route('/delete_images', methods=['POST'])
@login_required
def delete_images():
    if current_user.username != "h":
        return jsonify(success=False, error="Access denied"), 403
    data = request.get_json()
    images = data.get('images', [])
    images_base = os.path.join(os.getcwd(), "IMAGES")
    for img in images:
        key = img.get('key')
        filename = img.get('image')
        file_path = os.path.join(images_base, key, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
    return jsonify(success=True)

@app.route("/delete_user/<username>", methods=["POST"])
@login_required
def delete_user(username):
    if current_user.username != "h":
        flash("Access denied: Admin privileges required.")
        return redirect("/admin")

    db.execute("DELETE FROM users WHERE username = ?", username)
    flash(f"User '{username}' has been deleted.")
    return redirect("/admin")

# --- IMAGE UPLOAD, SERVE, AND AUTO-DELETE ---
UPLOAD_BASE = os.path.join(os.getcwd(), "IMAGES")

def delete_file_later(path, seconds=300):
    def remove():
        try:
            os.remove(path)
            # Optionally also remove empty group folder if no files left
            group_folder = os.path.dirname(path)
            if not os.listdir(group_folder):
                os.rmdir(group_folder)
        except Exception as e:
            print(f"Failed to delete {path}: {e}")
    timer = threading.Timer(seconds, remove)
    timer.start()

@app.route("/IMAGES/<key>/", methods=["POST"])
@login_required
def upload_image(key):
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    group_path = os.path.join(UPLOAD_BASE, str(key))
    os.makedirs(group_path, exist_ok=True)
    full_path = os.path.join(group_path, filename)
    file.save(full_path)

    # Schedule deletion in 5 minutes (300 seconds)
    delete_file_later(full_path, 300)

    # URL for fetching the image (should match the one used in your JS)
    image_url = url_for('serve_image', key=key, filename=filename)
    return jsonify({"image_url": image_url})

@app.route("/IMAGES/<key>/<filename>")
def serve_image(key, filename):
    return send_from_directory(os.path.join(UPLOAD_BASE, str(key)), filename)

# --- END IMAGE UPLOAD SECTION ---

from datetime import datetime, timedelta
timeouts = {}

@app.route("/mod", methods=["GET", "POST"])
@login_required
def mod_panel():
    # Normalize username (strip spaces, lowercase) for the check
    if current_user.username.strip().lower() not in ["h", "Diimi", "bu", "ct"]:
        flash("Access denied: Moderator privileges required.")
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username")
        timeout_duration = int(request.form.get("timeout_duration"))

        if timeout_duration < 1 or timeout_duration > 60:
            flash("Invalid timeout duration! Choose between 1 and 60 minutes.")
            return redirect(url_for("mod_panel"))

        timeout_until = (datetime.now() + timedelta(minutes=timeout_duration)).strftime("%Y-%m-%d %H:%M:%S")
        timeouts[username] = timeout_until

        flash(f"User {username} has been timed out for {timeout_duration} minutes!")
        return redirect(url_for("mod_panel"))

    users = [{"username": user["username"]} for user in db.execute("SELECT username FROM users")]
    return render_template("mod.html", users=users, timeouts=timeouts)

@app.route("/check_timeout")
@login_required
def check_timeout():
    timeout_until = timeouts.get(current_user.username)
    if timeout_until and datetime.now() < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return jsonify({"timed_out": True})
    return jsonify({"timed_out": False})

@app.route("/timeout-canceled")
@login_required
def timeout_canceled():
    timeout_until = timeouts.get(current_user.username)
    # If user is NOT in timeouts, their timeout has been canceled (or expired)
    if not timeout_until:
        return jsonify({"timeout_canceled": True})
    # If timeout is still in effect, return False
    if datetime.now() < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return jsonify({"timeout_canceled": False})
    # Timeout expired, remove from dict and return True
    del timeouts[current_user.username]
    return jsonify({"timeout_canceled": True})

@app.route("/cancel_timeout/<username>", methods=["POST"])
@login_required
def cancel_timeout(username):
    if current_user.username not in ["h", "ct", "bu", "Diimi"]:
        flash("Access denied: Moderator privileges required.")
        return redirect(url_for("mod_panel"))

    if username in timeouts:
        del timeouts[username]
        flash(f"Timeout for {username} has been canceled.")
    else:
        flash(f"{username} is already active.")

    return redirect(url_for("mod_panel"))

@app.route("/reset_messages", methods=["POST"])
@login_required
def reset_messages():
    if current_user.username != "h":
        flash("Access denied: Admin privileges required.")
        return redirect("/admin")
    try:
        with open("messages.json", "w") as file:
            json.dump({}, file)
        flash("All messages have been reset.")
    except Exception as e:
        flash(f"Error resetting messages: {str(e)}")
    return redirect(url_for("admin"))




DEFAULT_SETTINGS = {
    "profile_pic": None,
    "theme": "light",
    "notifications": True,
    "panic_url": "",
}

def get_settings_path(user_id):
    return os.path.join(SETTINGS_DIR, f"settings_{user_id}.pkl")

def load_user_settings(user_id):
    path = get_settings_path(user_id)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return DEFAULT_SETTINGS.copy()

def save_user_settings(user_id, settings):
    path = get_settings_path(user_id)
    with open(path, "wb") as f:
        pickle.dump(settings, f)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    settings = load_user_settings(current_user.id)
    if request.method == "POST":
        # Handle profile picture upload
        if "profile_pic" in request.files and request.files["profile_pic"].filename:
            file = request.files["profile_pic"]
            # Remove old profile picture if it exists and isn't default.png
            old_pic = settings.get("profile_pic")
            if old_pic and old_pic != "default.png":
                old_path = os.path.join("static", "profile_pics", old_pic)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception as e:
                        print(f"Failed to remove old profile picture: {e}")
            # Save new profile picture and resize it
            filename = f"profile_{current_user.id}_{secure_filename(file.filename)}"
            filepath = os.path.join("static", "profile_pics", filename)
            file.save(filepath)
            # Resize to 100x100 using Pillow
            try:
                with Image.open(filepath) as im:
                    im = im.convert("RGBA") if im.mode in ("P", "RGBA") else im.convert("RGB")
                    im = im.resize((100, 100), Image.LANCZOS)
                    im.save(filepath)
            except Exception as e:
                print(f"Error resizing profile picture: {e}")
            settings["profile_pic"] = filename

        # Theme selection
        if request.form.get("theme") in ["light", "dark", "yellow"]:
            settings["theme"] = request.form.get("theme")
        
        # Notifications
        settings["notifications"] = request.form.get("notifications") == "on"

        # Panic URL
        settings["panic_url"] = request.form.get("panic_url", "")

        # Password change
        new_password = request.form.get("new_password")
        if new_password:
            hashed_password = generate_password_hash(new_password)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, current_user.id)
            flash("Password changed!")

        # Save settings
        save_user_settings(current_user.id, settings)

        from flask import make_response
        resp = make_response(redirect(url_for("settings")))
        resp.set_cookie("notifications_enabled", "1" if settings["notifications"] else "0")
        flash("Settings updated!")
        return resp

    return render_template("settings.html", settings=settings, user=current_user)

@app.route("/delete_profile_pic/<username>", methods=["POST"])
@login_required
def delete_profile_pic(username):
    # Only admin can do this
    if current_user.username != "h":
        return jsonify(success=False, error="Access denied"), 403

    # Find user id by username
    user_row = db.execute("SELECT id FROM users WHERE username = ?", username)
    if not user_row:
        return jsonify(success=False, error="User not found"), 404
    user_id = user_row[0]["id"]

    # Load settings
    user_settings = load_user_settings(user_id)
    old_pic = user_settings.get("profile_pic")
    if old_pic and old_pic != "default.png":
        old_path = os.path.join("static", "profile_pics", old_pic)
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except Exception as e:
                print(f"Failed to remove profile picture: {e}")
    user_settings["profile_pic"] = "default.png"
    save_user_settings(user_id, user_settings)
    return jsonify(success=True)


from flask import jsonify, send_file

@app.route('/path/messages.json')
def serve_messages_json():
    try:
        # Option 1: Serve as application/json (recommended)
        import json
        with open('messages.json', 'r') as f:
            data = json.load(f)
        return jsonify(data)
        # Option 2: To force a download, use:
        # return send_file('messages.json', as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
import os
import json
from flask import request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timezone

TYPING_FILE = "typing.json"

def load_typing_data():
    if not os.path.exists(TYPING_FILE):
        return {}
    with open(TYPING_FILE, "r") as f:
        return json.load(f)

def save_typing_data(data):
    with open(TYPING_FILE, "w") as f:
        json.dump(data, f)

@app.route('/typing/<key>', methods=['POST'])
@login_required
def typing(key):
    username = current_user.username
    now = datetime.now(timezone.utc).isoformat()
    data = load_typing_data()
    if key not in data:
        data[key] = {}
    data[key][username] = now
    save_typing_data(data)
    return jsonify(success=True)

@app.route('/typing_stop/<key>', methods=['POST'])
@login_required
def typing_stop(key):
    username = current_user.username
    data = load_typing_data()
    if key in data and username in data[key]:
        del data[key][username]
        save_typing_data(data)
    return jsonify(success=True)

@app.route('/typing_status/<key>')
@login_required
def typing_status(key):
    now = datetime.now(timezone.utc)
    data = load_typing_data()
    active_typers = []
    changed = False
    if key in data:
        for username, last_time_str in list(data[key].items()):
            last_time = datetime.fromisoformat(last_time_str)
            if (now - last_time).total_seconds() > 3:
                del data[key][username]
                changed = True
            else:
                active_typers.append(username)
        if changed:
            save_typing_data(data)
    return jsonify(typing=active_typers)

@app.route('/terms')
def terms_and_conditions():
    return render_template('policy.html')

if __name__ == "__main__":
    # Ensure IMAGES directory exists
    if not os.path.exists(UPLOAD_BASE):
        os.makedirs(UPLOAD_BASE)
    app.run(debug=True)