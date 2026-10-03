from flask import Flask, render_template, request, redirect, url_for, session
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

# Demo TOTP secret
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

totp = pyotp.TOTP(TOTP_SECRET)

MAX_ATTEMPTS = 3


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "vicky" and password == "vicky123":

            session["username"] = username
            session["failed_attempts"] = 0
            session["locked"] = False
            log_auth_event(username, "PASSWORD_LOGIN", "SUCCESS", "Username and password verified")

            return redirect(url_for("token"))

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

    current_otp = totp.now()

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

    # Verify OTP
    if totp.verify(entered_otp):
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

    # Wrong OTP
    failed_attempts = session.get("failed_attempts", 0) + 1
    session["failed_attempts"] = failed_attempts

    log_auth_event(
    session["username"],
    "MFA_OTP",
    "FAILURE",
    f"Invalid OTP attempt {failed_attempts} of {MAX_ATTEMPTS}"
)

    # Lock after 3 failed attempts
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
            locked=True
        )

    current_otp = totp.now()
    remaining_seconds = 30 - (int(time.time()) % 30)

    return render_template(
        "token.html",
        username=session["username"],
        otp=current_otp,
        remaining_seconds=remaining_seconds,
        attempts=failed_attempts,
        error=f"Invalid OTP. Attempt {failed_attempts} of {MAX_ATTEMPTS}."
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)