import os
import time
import datetime
import secrets
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

# ================== CONFIG ==================
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///student_portal.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
CORS(app, origins=[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
], supports_credentials=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)  # vulnerable on purpose
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class AuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship("User", backref=db.backref("tokens", lazy=True))


def seed_mock_user():
    existing = {user.email for user in User.query.all()}
    mock_users = [
        ("test@student.com", "password123"),
        ("test1@student.com", "password123"),
    ]

    created_any = False
    for email, password in mock_users:
        if email in existing:
            continue
        mock = User(email=email, password_hash=generate_password_hash(password))
        db.session.add(mock)
        created_any = True

    if created_any:
        db.session.commit()
        print("[+] Mock users ensured:", ", ".join(email for email, _ in mock_users))


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    AuthToken.query.filter_by(user_id=user.id).delete()
    token = secrets.token_hex(32)
    auth_token = AuthToken(user_id=user.id, token=token)
    db.session.add(auth_token)
    db.session.commit()

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "email": user.email
        },
        "token": token
    })


def serialize_document(doc: Document):
    return {
        "id": doc.id,
        "original_name": doc.original_name,
        "stored_name": doc.stored_name,
        "uploaded_at": doc.uploaded_at.isoformat()
    }


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        auth = AuthToken.query.filter_by(token=token).first()
        if not auth:
            return jsonify({"error": "Invalid or expired token"}), 401

        return fn(*args, **kwargs)
    return wrapper


@app.route("/api/documents/upload", methods=["POST"])
@auth_required
def upload_document():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files["file"]
    user_id = request.form.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id required"}), 400


    timestamp = int(time.time())
    stored_name = f"{user_id}_{timestamp}_{file.filename}"

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    file.save(save_path)

    doc = Document(
        user_id=int(user_id),
        original_name=file.filename,
        stored_name=stored_name
    )
    db.session.add(doc)
    db.session.commit()

    return jsonify({
        "message": "uploaded",
        "document": serialize_document(doc)
    })


# ================== LIST FILES ==================
@app.route("/api/documents", methods=["GET"])
@auth_required
def list_documents():
    user_id = request.args.get("user_id")

    # vulnerable: user sends any user_id and sees their files
    docs = Document.query.filter_by(user_id=user_id).all()

    return jsonify([serialize_document(d) for d in docs])


# ================== DOWNLOAD FILE ==================
@app.route("/api/documents/download", methods=["GET"])
@auth_required
def download_document():
    doc_id = request.args.get("file_id", type=int)

    if not doc_id:
        return jsonify({"error": "file_id required"}), 400

    doc = Document.query.get(doc_id)

    if not doc:
        return jsonify({"error": "File not found"}), 404

    # vulnerable: no check if the file belongs to logged user
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        doc.stored_name,
        as_attachment=True
    )



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_mock_user()

    app.run(debug=True)
