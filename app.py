from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import time
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

app = Flask(__name__)

# Firebase Firestore connection
firebase_json = os.environ.get("FIREBASE_CREDENTIALS")

if firebase_json:
    cred = credentials.Certificate(json.loads(firebase_json))
else:
    cred = credentials.Certificate("firebase_key.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

def log_auth_event(username, event, status, details=""):
    db.collection("authentication_logs").add({
        "username": username,
        "event": event,
        "status": status,
        "details": details,
        "timestamp": firestore.SERVER_TIMESTAMP
    })
app.secret_key = "mfa-project-secret-key-2026"

MAX_ATTEMPTS = 3


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Find user in Firestore
        user_ref = db.collection("users").document(username)
        user_doc = user_ref.get()

        if user_doc.exists:

            user_data = user_doc.to_dict()

            # Check password
            if check_password_hash(
                user_data.get("password_hash", ""),
                password
            ):

                session["username"] = username
                session["failed_attempts"] = 0
                session["locked"] = False

                # Store this user's TOTP secret
                session["totp_secret"] = user_data.get("totp_secret")

                log_auth_event(
                    username,
                    "PASSWORD_LOGIN",
                    "SUCCESS",
                    "Username and password verified"
                )

                return redirect(url_for("token"))

        # Login failed
        log_auth_event(
            username,
            "PASSWORD_LOGIN",
            "FAILURE",
            "Invalid username or password"
        )

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


@app.route("/token")
def token():

    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("locked", False):
        return render_template(
            "token.html",
            username=session["username"],
            locked=True
        )

    # Get this user's personal TOTP secret
    user_totp_secret = session.get("totp_secret")

    if not user_totp_secret:
        return redirect(url_for("login"))

    # Generate this user's current OTP
    user_totp = pyotp.TOTP(user_totp_secret)
    current_otp = user_totp.now()

    # Calculate remaining seconds
    remaining_seconds = 30 - (int(time.time()) % 30)

    return render_template(
        "token.html",
        username=session["username"],
        otp=current_otp,
        remaining_seconds=remaining_seconds,
        attempts=session.get("failed_attempts", 0)
    )


@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    if "username" not in session:
        return redirect(url_for("login"))

    # Check whether account is locked
    if session.get("locked", False):
        return render_template(
            "token.html",
            username=session["username"],
            locked=True
        )

    entered_otp = request.form.get("otp", "").strip()

    # Get this user's personal TOTP secret
    user_totp_secret = session.get("totp_secret")

    if not user_totp_secret:
        return redirect(url_for("login"))

    # Create TOTP object for this user
    user_totp = pyotp.TOTP(user_totp_secret)

    # Verify OTP
    if user_totp.verify(entered_otp):

        session["failed_attempts"] = 0

        log_auth_event(
            session["username"],
            "MFA_OTP",
            "SUCCESS",
            "One-time password verified successfully"
        )

        return render_template(
            "dashboard.html",
            username=session["username"]
        )

    # OTP verification failed
    failed_attempts = session.get("failed_attempts", 0) + 1
    session["failed_attempts"] = failed_attempts

    log_auth_event(
        session["username"],
        "MFA_OTP",
        "FAILURE",
        f"Invalid OTP attempt {failed_attempts} of {MAX_ATTEMPTS}"
    )

    # Lock account after maximum attempts
    if failed_attempts >= MAX_ATTEMPTS:

        session["locked"] = True

        log_auth_event(
            session["username"],
            "MFA_OTP",
            "FAILED",
            f"OTP verification failed {failed_attempts} times; account locked"
        )

        return render_template(
            "token.html",
            username=session["username"],
            locked=True,
            attempts=failed_attempts
        )

    # Show token page again with updated attempt count
    user_totp = pyotp.TOTP(user_totp_secret)
    current_otp = user_totp.now()
    remaining_seconds = 30 - (int(time.time()) % 30)

    return render_template(
        "token.html",
        username=session["username"],
        otp=current_otp,
        remaining_seconds=remaining_seconds,
        attempts=failed_attempts,
        error="Invalid OTP. Please try again."
    )


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Check required fields
        if not username or not password or not confirm_password:
            return render_template(
                "register.html",
                error="All fields are required."
            )

        # Check password match
        if password != confirm_password:
            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        # Check password length
        if len(password) < 6:
            return render_template(
                "register.html",
                error="Password must be at least 6 characters."
            )

        # Check whether username already exists
        user_ref = db.collection("users").document(username)
        user_doc = user_ref.get()

        if user_doc.exists:
            return render_template(
                "register.html",
                error="Username already exists. Please choose another."
            )

        # Generate a unique MFA TOTP secret
        user_totp_secret = pyotp.random_base32()

        # Store user securely in Firestore
        user_ref.set({
            "username": username,
            "password_hash": generate_password_hash(password),
            "totp_secret": user_totp_secret,
            "created_at": firestore.SERVER_TIMESTAMP
        })

        # Log registration
        log_auth_event(
            username,
            "USER_REGISTERED",
            "SUCCESS",
            "New user account created"
        )

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)