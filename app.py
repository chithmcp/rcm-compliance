
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_connection


app = Flask(__name__)

# Secret key for Flask sessions
# Change this to a long random value later
app.secret_key = "my-secret-key-change-this"


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():
    return redirect(url_for("login"))


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Check empty fields
        if not name or not email or not password:
            return render_template(
                "register.html",
                error="Please fill in all fields."
            )

        # Check password length
        if len(password) < 6:
            return render_template(
                "register.html",
                error="Password must be at least 6 characters."
            )

        connection = None

        try:

            # Connect to MySQL
            connection = get_connection()
            cursor = connection.cursor()

            # Check whether email already exists
            cursor.execute(
                "SELECT Id FROM Users WHERE Email = %s",
                (email,)
            )

            existing_user = cursor.fetchone()

            if existing_user:

                return render_template(
                    "register.html",
                    error="Email already exists."
                )

            # Hash password
            password_hash = generate_password_hash(password)

            # Insert user into MySQL
            cursor.execute(
                """
                INSERT INTO Users
                (Name, Email, PasswordHash)
                VALUES (%s, %s, %s)
                """,
                (name, email, password_hash)
            )

            connection.commit()

            return redirect(url_for("login"))

        except Exception as e:

            print("MySQL database error:", e)

            return render_template(
                "register.html",
                error="Database error occurred."
            )

        finally:

            if connection:
                connection.close()


    return render_template("register.html")


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Check empty fields
        if not email or not password:

            return render_template(
                "login.html",
                error="Please enter email and password."
            )

        connection = None

        try:

            # Connect to MySQL
            connection = get_connection()
            cursor = connection.cursor()

            # Find user by email
            cursor.execute(
                """
                SELECT Id, Name, Email, PasswordHash
                FROM Users
                WHERE Email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            # User not found
            if user is None:

                return render_template(
                    "login.html",
                    error="Invalid email or password."
                )

            # Get user information
            user_id = user[0]
            user_name = user[1]
            user_email = user[2]
            password_hash = user[3]

            # Verify password
            if check_password_hash(
                password_hash,
                password
            ):

                # Store information in Flask session
                session["user_id"] = user_id
                session["user_name"] = user_name
                session["user_email"] = user_email

                return redirect(
                    url_for("dashboard")
                )

            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        except Exception as e:

            print("MySQL database error:", e)

            return render_template(
                "login.html",
                error="Database error occurred."
            )

        finally:

            if connection:
                connection.close()


    return render_template("login.html")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    # Make sure user is logged in
    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        name=session["user_name"],
        email=session["user_email"]
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    # Remove all session data
    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# START FLASK
# ==========================================

if __name__ == "__main__":

    app.run(debug=True)

