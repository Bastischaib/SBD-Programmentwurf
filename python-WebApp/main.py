from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_socketio import join_room, leave_room, send, SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import random
from config.config import SECRET_KEY
from string import ascii_uppercase
from datetime import datetime
from sqlalchemy.orm import validates

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
socketio = SocketIO(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

rooms = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @validates('content')
    def validate_content(self, key, value):
        if not value.strip():
            raise ValueError('Message content must not be empty or whitespace.')
        return value

def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    
    return code

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "login" in request.form:
            return redirect(url_for("login"))
        elif "register" in request.form:
            return redirect(url_for("register"))

    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password. Please try again.", "error")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists. Choose a different one.", "error")
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. You can now log in.", "success")

            # Direkte Weiterleitung nach der Registrierung
            session["user_id"] = new_user.id
            session["username"] = new_user.username
            return redirect(url_for("home"))

    return render_template("register.html")

@app.route("/home", methods=["GET", "POST"])
def home():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code")
        join = "join" in request.form
        create = "create" in request.form

        if join and not code:
            flash("Please enter a room code.", "error")
        else:
            room = code if join else generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": []}
            session["room"] = room
            return redirect(url_for("room"))

    return render_template("home.html")

@app.route("/room")
def room():
    room = session.get("room")
    if not room or room not in rooms:
        return redirect(url_for("home"))

    messages = Message.query.all()

    return render_template("room.html", code=room, messages=messages)

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    content = {
        "name": session.get("username"),
        "message": data["data"]
    }

    new_message = Message(content=content["message"], user_id=User.query.filter_by(username=content["name"]).first().id)
    db.session.add(new_message)
    db.session.commit()

    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('username')} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    username = session.get("username")
    if not room or not username:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": username, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{username} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    username = session.get("username")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    send({"name": username, "message": "has left the room"}, to=room)
    print(f"{username} has left the room {room}")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        socketio.run(app, debug=True)
