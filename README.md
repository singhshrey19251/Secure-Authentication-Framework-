# Secure-Authentication-Framework-
import os
import random
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)

users = {}
active_sessions = {}
security_logs = []

EVENT_SEVERITY = {
    "LOGIN_SUCCESS": "INFO",
    "LOGIN_FAILED": "WARNING",
    "OTP_SENT": "INFO",
    "MFA_SUCCESS": "INFO",
    "MFA_FAILED": "WARNING",
    "ACCOUNT_LOCKED": "CRITICAL",
    "BRUTE_FORCE_ATTACK": "CRITICAL",
    "PRIVILEGE_MISUSE": "CRITICAL",
    "SESSION_TERMINATED": "WARNING",
    "PASSWORD_CHANGED": "INFO",
    "MFA_ENABLED": "INFO",
    "MFA_DISABLED": "WARNING",
}

SPECIAL_CHARS = r"!@#$%^&*()_+-=[]{}|;:,.<>?/"


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def random_ip():
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"


def default_message(event_type, username):
    messages = {
        "LOGIN_SUCCESS": f"Successful OS authentication for {username}",
        "LOGIN_FAILED": f"Failed credential attempt detected for {username}",
        "OTP_SENT": f"Six-digit MFA token generated for {username}",
        "MFA_SUCCESS": f"MFA verification completed for {username}",
        "MFA_FAILED": f"Invalid or expired MFA token attempt for {username}",
        "ACCOUNT_LOCKED": f"Account locked after repeated failed attempts for {username}",
        "BRUTE_FORCE_ATTACK": f"Brute force attack pattern detected against {username}",
        "PRIVILEGE_MISUSE": f"Privilege misuse pattern detected for {username}",
        "SESSION_TERMINATED": f"Active session terminated for {username}",
        "PASSWORD_CHANGED": f"Password changed for {username}",
        "MFA_ENABLED": f"MFA enabled for {username}",
        "MFA_DISABLED": f"MFA disabled for {username}",
    }
    return messages.get(event_type, "Security event recorded")


def add_log(event_type, username="system", ip=None, severity=None, message=""):
    entry = {
        "timestamp": timestamp(),
        "event_type": event_type,
        "username": username,
        "ip": ip or random_ip(),
        "severity": severity or EVENT_SEVERITY.get(event_type, "INFO"),
        "message": message or default_message(event_type, username),
    }
    security_logs.insert(0, entry)
    del security_logs[250:]
    return entry


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def validate_password(password):
    errors = []

    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("one number")
    if not any(char in SPECIAL_CHARS for char in password):
        errors.append("one special character")

    if errors:
        return False, "Password must include " + ", ".join(errors) + "."

    return True, "Strong password accepted."


def generate_otp():
    return f"{random.randint(0, 999999):06d}"


def seed_user():
    if "analyst" not in users:
        users["analyst"] = {
            "username": "analyst",
            "email": "analyst@soc.local",
            "password": hash_password("SecurePass123!"),
            "created": timestamp(),
            "last_login": "Never",
            "failed_attempts": 0,
            "locked": False,
            "mfa_enabled": True,
            "known_ips": [],
        }
        add_log(
            "LOGIN_SUCCESS",
            "analyst",
            "10.0.0.10",
            "INFO",
            "Default analyst account initialized",
        )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            flash("Authentication required.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    return users.get(session.get("user"))


def simulate_attack_event():
    targets = list(users.keys()) or ["unknown"]

    event_type = random.choices(
        [
            "LOGIN_FAILED",
            "MFA_FAILED",
            "BRUTE_FORCE_ATTACK",
            "PRIVILEGE_MISUSE",
            "MFA_SUCCESS",
        ],
        weights=[30, 18, 18, 14, 20],
        k=1,
    )[0]

    username = random.choice(targets)
    ip = random_ip()

    messages = {
        "LOGIN_FAILED": "Invalid password submitted from monitored endpoint",
        "MFA_FAILED": "MFA challenge failed during OS login sequence",
        "BRUTE_FORCE_ATTACK": f"{random.randint(18, 88)} rapid login attempts detected from same origin",
        "PRIVILEGE_MISUSE": "Admin-level action attempted from untrusted location",
        "MFA_SUCCESS": "MFA completed during active authentication cycle",
    }

    return add_log(
        event_type,
        username,
        ip,
        EVENT_SEVERITY[event_type],
        messages[event_type],
    )


def count_events(event_types):
    return {
        event_type: sum(
            1 for log in security_logs if log["event_type"] == event_type
        )
        for event_type in event_types
    }


def severity_counts():
    return {
        level: sum(1 for log in security_logs if log["severity"] == level)
        for level in ["INFO", "WARNING", "CRITICAL"]
    }


def chart_data():
    login_outcomes = {
        "Successful Logins": sum(
            1 for log in security_logs if log["event_type"] == "LOGIN_SUCCESS"
        ),
        "Failed Logins": sum(
            1 for log in security_logs if log["event_type"] == "LOGIN_FAILED"
        ),
        "MFA Verifications": sum(
            1 for log in security_logs if log["event_type"] == "MFA_SUCCESS"
        ),
    }

    frequency = count_events(
        [
            "LOGIN_FAILED",
            "LOGIN_SUCCESS",
            "MFA_FAILED",
            "ACCOUNT_LOCKED",
            "BRUTE_FORCE_ATTACK",
        ]
    )

    return {
        "login_outcomes": login_outcomes,
        "severity": severity_counts(),
        "frequency": frequency,
    }


def threat_logs():
    return [
        log
        for log in security_logs
        if log["event_type"]
        in {
            "BRUTE_FORCE_ATTACK",
            "PRIVILEGE_MISUSE",
            "ACCOUNT_LOCKED",
            "LOGIN_FAILED",
        }
    ][:12]


@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    seed_user()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Username, email, and password are required.", "error")
            return redirect(url_for("register"))

        if username in users:
            flash("That username already exists.", "error")
            return redirect(url_for("register"))

        valid, message = validate_password(password)

        if not valid:
            flash(message, "error")
            return redirect(url_for("register"))

        users[username] = {
            "username": username,
            "email": email,
            "password": hash_password(password),
            "created": timestamp(),
            "last_login": "Never",
            "failed_attempts": 0,
            "locked": False,
            "mfa_enabled": True,
            "known_ips": [],
        }

        add_log(
            "LOGIN_SUCCESS",
            username,
            client_ip(),
            "INFO",
            "New OS user account registered securely",
        )

        flash("Account created. Sign in to continue.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    seed_user()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = users.get(username)
        ip = client_ip()

        if not user:
            add_log("LOGIN_FAILED", username or "unknown", ip)
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        if user["locked"]:
            add_log("ACCOUNT_LOCKED", username, ip)
            flash("Account is locked because of repeated failed attempts.", "error")
            return redirect(url_for("login"))

        if not check_password(password, user["password"]):
            user["failed_attempts"] += 1

            if user["failed_attempts"] > 5:
                user["locked"] = True
                add_log("ACCOUNT_LOCKED", username, ip)
                add_log(
                    "BRUTE_FORCE_ATTACK",
                    username,
                    ip,
                    "CRITICAL",
                    "More than 5 failed login attempts detected",
                )
                flash("Account locked after more than 5 failed attempts.", "error")
            else:
                add_log("LOGIN_FAILED", username, ip)
                flash(
                    f"Invalid username or password. Attempt {user['failed_attempts']} of 5.",
                    "error",
                )

            return redirect(url_for("login"))

        user["failed_attempts"] = 0

        otp = generate_otp()

        session["pending_user"] = username
        session["otp"] = otp
        session["otp_expires"] = time.time() + 30

        add_log(
            "OTP_SENT",
            username,
            ip,
            "INFO",
            "Simulated OTP generated for MFA verification",
        )

        return redirect(url_for("otp"))

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    remaining = max(0, int(session.get("otp_expires", 0) - time.time()))

    if request.method == "POST":
        username = session.get("pending_user")
        user = users.get(username)
        ip = client_ip()

        entered = request.form.get("otp", "") or "".join(
            request.form.getlist("digit")
        )

        if time.time() > session.get("otp_expires", 0):
            add_log(
                "MFA_FAILED",
                username,
                ip,
                "WARNING",
                "OTP expired before verification",
            )
            flash("OTP expired. Please sign in again.", "error")

            session.pop("pending_user", None)
            session.pop("otp", None)
            session.pop("otp_expires", None)

            return redirect(url_for("login"))

        if entered == session.get("otp"):
            sid = uuid.uuid4().hex[:16].upper()

            session["user"] = username
            session["session_id"] = sid

            session.pop("pending_user", None)
            session.pop("otp", None)
            session.pop("otp_expires", None)

            user["last_login"] = timestamp()

            known_ips = user.setdefault("known_ips", [])

            if known_ips and ip not in known_ips:
                add_log(
                    "PRIVILEGE_MISUSE",
                    username,
                    ip,
                    "CRITICAL",
                    "Suspicious login from unknown IP after previous session history",
                )

            if ip not in known_ips:
                known_ips.append(ip)

            active_user_ips = {
                session_data["ip"]
                for session_data in active_sessions.values()
                if session_data["user"] == username
            }

            if len(active_user_ips | {ip}) > 1:
                add_log(
                    "PRIVILEGE_MISUSE",
                    username,
                    ip,
                    "CRITICAL",
                    "Multiple active logins from different IP addresses",
                )

            active_sessions[sid] = {
                "id": sid,
                "status": "LIVE",
                "user": username,
                "ip": ip,
                "login_time": timestamp(),
                "expiry": (datetime.now() + timedelta(hours=2)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }

            add_log("LOGIN_SUCCESS", username, ip)
            add_log("MFA_SUCCESS", username, ip)

            return redirect(url_for("dashboard"))

        add_log("MFA_FAILED", username, ip)
        flash("Invalid OTP.", "error")

    return render_template("otp.html", otp=session.get("otp"), remaining=remaining)


@app.route("/logout")
def logout():
    sid = session.get("session_id")
    username = session.get("user", "unknown")

    if sid in active_sessions:
        active_sessions.pop(sid)
        add_log("SESSION_TERMINATED", username, client_ip())

    session.clear()
    flash("Session closed.", "success")

    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    while len(security_logs) < 12:
        simulate_attack_event()

    return render_template(
        "dashboard.html",
        user=current_user(),
        chart_data=chart_data(),
        logs=security_logs[:12],
        threat_logs=threat_logs(),
        active_count=len(active_sessions),
    )


@app.route("/sessions")
@login_required
def sessions_page():
    return render_template(
        "sessions.html",
        user=current_user(),
        sessions=list(active_sessions.values()),
    )


@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html", user=current_user(), logs=security_logs[:100])


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "toggle_mfa":
            user["mfa_enabled"] = not user["mfa_enabled"]
            add_log(
                "MFA_ENABLED" if user["mfa_enabled"] else "MFA_DISABLED",
                user["username"],
                client_ip(),
            )
            flash("MFA setting updated.", "success")

        elif action == "change_password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")

            valid, message = validate_password(new)

            if not check_password(current, user["password"]):
                flash("Current password is incorrect.", "error")
            elif not valid:
                flash(message, "error")
            else:
                user["password"] = hash_password(new)
                add_log("PASSWORD_CHANGED", user["username"], client_ip())
                flash("Password changed successfully.", "success")

    return render_template("profile.html", user=user)


@app.route("/terminate/<sid>", methods=["POST"])
@login_required
def terminate(sid):
    target = active_sessions.pop(sid, None)

    if target:
        add_log(
            "SESSION_TERMINATED",
            target["user"],
            client_ip(),
            "WARNING",
            f"Session {sid} terminated by operator",
        )

        if sid == session.get("session_id"):
            session.clear()
            flash("Your current session was terminated.", "warning")
            return redirect(url_for("login"))

    return redirect(url_for("sessions_page"))


@app.route("/api/metrics")
@login_required
def api_metrics():
    if random.random() > 0.30:
        simulate_attack_event()

    return jsonify(
        {
            "cpu": random.randint(21, 96),
            "memory": random.randint(34, 91),
            "processes": random.randint(118, 468),
            "active_sessions": len(active_sessions),
            "chart_data": chart_data(),
            "logs": security_logs[:14],
            "threat_logs": threat_logs(),
            "threats": [
                {
                    "level": "CRITICAL",
                    "text": "Brute force attack activity detected",
                },
                {
                    "level": "CRITICAL",
                    "text": "Privilege misuse from unknown IP flagged",
                },
                {
                    "level": "WARNING",
                    "text": "Multiple failed login attempts under observation",
                },
            ],
        }
    )


@app.route("/api/logs")
@login_required
def api_logs():
    if random.random() > 0.45:
        simulate_attack_event()

    return jsonify({"logs": security_logs[:100], "chart_data": chart_data()})


@app.route("/api/sessions")
@login_required
def api_sessions():
    return jsonify({"sessions": list(active_sessions.values())})


if __name__ == "__main__":
    seed_user()

    for _ in range(12):
        simulate_attack_event()

    app.run(debug=True, host="0.0.0.0", port=5000)
