# Jacky Li
# 2022/12/26
# CS50
# School Master
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from email.message import EmailMessage
import ssl
import smtplib

from helpers import login_required

# Initialize the email sender and the google set up password
email_sender = 'studentmaster679@gmail.com'
email_password = "ncdnpzddzrlhlpea"

# Locate the folder that the image uploads will go to and limit the type of uploads
UPLOAD_FOLDER = '/Users/jackyli/Visual Studio Projects/CS50/92805289/project/static/images'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Configure application
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


 # https://flask.palletsprojects.com/en/2.2.x/patterns/fileuploads/
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


# Type of subjects allowed
TYPES = [
    "Math",
    "English Literature",
    "Physics",
    "Biology",
    "Chemistry",
    "Computer Science",
    "Essay Writing",
    "Other"
]


# Homepage
@app.route("/")
@login_required
def index():

    # Get the current user's username
    username = db.execute("SELECT username FROM users WHERE id = (?)", session["user_id"])

    # Query database for the number of different types of sessions in the database
    posted_sessions = len(db.execute("SELECT * FROM sessions WHERE status = 'posted' and user_id = (?);", session['user_id']))

    awaiting_sessions = len(db.execute("SELECT * FROM sessions WHERE status = 'awaiting for confirmation' and user_id = (?);", session['user_id']))

    in_progress_sessions = len(db.execute("SELECT * FROM sessions WHERE status = 'registered' and user_id = (?);", session['user_id']))

    registered_sessions = len(db.execute(
        "SELECT * FROM sessions JOIN user_sessions WHERE user_sessions.session_id = sessions.id AND user_sessions.user_id = (?) AND user_sessions.relationship = 'registered';", session["user_id"]))

    return render_template("index.html", username=username, posted_sessions=posted_sessions, awaiting_sessions=awaiting_sessions, in_progress_sessions=in_progress_sessions, registered_sessions=registered_sessions)


# login page
@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    # User reached route through POST
    if request.method == "POST":

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure password and username is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("notification.html", message="Invalid username and/or password", link="/login", button_message="Return back to Log in")

        session["user_id"] = rows[0]["id"]

        return redirect("/")

    # User reached route through GET
    else:
        return render_template("login.html")



# Log out
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# Sign up page
@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():

    # User reached the route through POST - submitted the form
    if request.method == "POST":

        # Get all the inputs
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        confirmation = request.form.get("confirmation")

        # Query database for rows that has the same username
        list = db.execute("SELECT * FROM users WHERE username = (?)", username)

        # Make sure no repeated usernames
        if len(list) != 0:
            return render_template("notification.html", message="Username Existed!", link="/sign_up", button_message="Return back to Sign Up")

        # Make sure password matches confirmation
        if password != confirmation:
            return render_template("notification.html", message="Password Does Not Match Confirmation", link="/sign_up", button_message="Return back to Sign Up")

        # Insert user data into database
        db.execute("INSERT INTO users (username, email, hash) VALUES(?,?, ?)",
                   username, email, generate_password_hash(password))

        # Log user in
        session["user_id"] = db.execute(
            "SELECT id FROM users WHERE username = (?);", username)[0]['id']

        return redirect("/")

    # User reached route through GET
    else:
        return render_template("sign_up.html")


# Discover Page
@app.route("/discover", methods=["GET", "POST"])
def discover():

    # User reached route through POST
    if request.method == "POST":
        filename_received = ''
        # https://flask.palletsprojects.com/en/2.2.x/patterns/fileuploads/
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return render_template("notification.html", message="Invalid Upload Type", link="/discover", button_message="Return back To Discover")
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            filename_received = filename
        

        if filename_received == '':
            return render_template("notification.html", message="Invalid Upload Type", link="/discover", button_message="Return back To Discover")
        
        # Get all the inputs
        description = request.form.get('description')
        if not description:
            description = ''
        title = request.form.get('title')
        type = request.form.get('type')

        # Insert data into database
        db.execute("INSERT INTO sessions (user_id, title, image_name, description, type, status) VALUES(?,?,?,?,?,'posted');",
                   session["user_id"], title, filename, description, type)

        # Insert data into the database where it stores the relationships between users and sessions
        session_id = db.execute(
            "SELECT id FROM sessions WHERE image_name = (?);", filename)

        db.execute("INSERT INTO user_sessions (user_id, session_id, relationship) VALUES(?,?,'posted')",
                   session["user_id"], session_id[0]["id"])

        # Print all the sessions on Discover Page
        sessions = db.execute("SELECT * FROM sessions WHERE status='posted';")

        return render_template('discover.html', types=TYPES, sessions=sessions, current_user=session["user_id"])

    # User reached route through GET
    else:
        # Print all the sessions on Discover Page
        sessions = db.execute("SELECT * FROM sessions WHERE status='posted';")
        return render_template("discover.html", types=TYPES, sessions=sessions, current_user=session["user_id"])


# Sessions Page
@app.route("/sessions")
@login_required
def sessions():

    # Query database to get information for all types of sessions related to the current user
    posted_sessions = db.execute(
        "SELECT * FROM sessions WHERE user_id = (?) AND status = 'posted';", session["user_id"])
    registered_sessions = db.execute(
        "SELECT * FROM sessions JOIN user_sessions WHERE user_sessions.session_id = sessions.id AND user_sessions.user_id = (?) AND user_sessions.relationship = 'registered';", session["user_id"])
    in_progress_sessions = db.execute(
        "SELECT * FROM sessions WHERE status = 'registered' AND user_id = (?)", session["user_id"])
    awaiting_sessions = db.execute(
        "SELECT sessions.image_name, sessions.id, sessions.title, sessions.description, sessions.user_id, sessions.type, users.username from sessions JOIN users WHERE sessions.status = 'awaiting for confirmation' and sessions.user_id = (?) and users.id = (SELECT user_sessions.user_id from user_sessions join sessions where user_sessions.session_id = sessions.id AND user_sessions.relationship = 'awaiting for confirmation');", session["user_id"])
    return render_template("sessions.html", posted_sessions=posted_sessions, registered_sessions=registered_sessions, in_progress_sessions=in_progress_sessions, awaiting_sessions=awaiting_sessions)


# method for user registered other users' sessions
@app.route("/register")
@login_required
def register():
    # Get the selected session's id
    session_id = request.args.get("session_id")

    # Change the status of the session
    db.execute(
        "UPDATE sessions SET status = 'awaiting for confirmation' WHERE id = (?)", session_id)

    # Get the email of the user who posted the session
    email_receiver = db.execute(
        "SELECT email FROM users JOIN sessions WHERE sessions.id = (?) AND sessions.user_id = users.id", session_id)
    email_receiver = email_receiver[0]['email']

    # Update database where it stores the relationship between users and sessions
    db.execute(
        "INSERT INTO user_sessions (user_id, session_id, relationship) VALUES (?,?,'awaiting for confirmation')", session["user_id"], session_id)

    # Query database to get information
    session_info = db.execute(
        "SELECT users.username, sessions.title FROM sessions JOIN users WHERE sessions.id = (?) AND sessions.user_id = users.id", session_id)
    current_username = db.execute(
        "SELECT username FROM users WHERE id = (?)", session["user_id"])

    # Set up email subject and message
    subject = current_username[0]['username'] + \
        " has requested to register your session: " + session_info[0]["title"]
    message = "Hello, " + session_info[0]["username"] + ". This is a notification from School Master. Your uploaded session: " + session_info[0]["title"] + " has been registered by user: " + \
        current_username[0]['username'] + ".\n Please go to our website to confirm the request.\n" + \
        "We will provide " + \
        current_username[0]['username'] + \
        "'s email address after you have confirmed."

    # Set up email sender, receiver, subject, and message
    msg = EmailMessage()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['subject'] = subject
    msg.set_content(message)

    context = ssl.create_default_context()

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, msg.as_string())

    # Return to notification page indicating the user that the process is complete
    return render_template("notification.html", message="We have successfully sent a confirmation to your requested user! You will receive an email notification when the user has responded.", link="/sessions", button_message="Return to Sessions")


# Details of a session
@app.route("/detailed_session")
@login_required
def detailed_session():
    # Get inputs
    session_id = request.args.get("session_id")
    user_id = request.args.get("user_id")
    previous_page = request.args.get("previous_page")

    # Query database to get information of a session and user that the session belongs to
    session_info = db.execute(
        "SELECT * FROM sessions WHERE id = (?)", session_id)
    user_info = db.execute("SELECT * FROM users WHERE id = (?)", user_id)

    # Return to detailed session page
    return render_template("detailed.html", session_info=session_info, user_info=user_info, previous_page=previous_page, current_user=session["user_id"])


# User confirm the request
@app.route("/confirm", methods=["POST"])
@login_required
def confirm():
    # Get information
    session_id = request.form.get("session_id")
    previous_page = request.form.get("previous_page")

    # Get information of the user who registered the session of the current user
    registered_user_info = db.execute(
        "SELECT username, email FROM users JOIN user_sessions WHERE user_sessions.user_id = users.id AND user_sessions.session_id = (?) AND user_sessions.relationship = 'awaiting for confirmation'", session_id)

    # Update database
    db.execute("UPDATE user_sessions SET relationship = 'registered' WHERE session_id = (?) AND relationship = 'awaiting for confirmation'", session_id)
    db.execute("UPDATE sessions SET status = 'registered' WHERE id = (?)", session_id)

    # Get session info
    session_info = db.execute(
        "SELECT * FROM sessions WHERE id = (?)", session_id)

    # Get current user info
    posted_user_info = db.execute(
        "SELECT * FROM users WHERE id = (?)", session["user_id"])

    # Set up the email receiver for the registered user
    email_receiver = registered_user_info[0]["email"]

    # Set up message and subject for the email
    subject = posted_user_info[0]["username"] + " has accepted your request on the session: " + session_info[0]["title"]

    message = posted_user_info[0]["username"] + " has just accpeted your request. Here is his/her email address: " + posted_user_info[0]['email'] + "\nYou can contact this user to arrange private meeting sessions."

    # Set up sender, receiver, subject, and message for the registered user
    msg = EmailMessage()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['subject'] = subject
    msg.set_content(message)

    context = ssl.create_default_context()

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, msg.as_string())

    # Set up email for the current user
    subject = "You have accpeted the request from " + registered_user_info[0]["username"]

    message = "You just accepeted the request from " + registered_user_info[0]["username"] + " on your session: " + session_info[0]["title"] + "\nHere is " + registered_user_info[0]["username"] + "'s email address: " + registered_user_info[0]["email"] + "\nPlease remember to end the session on our website when it's finished."

    # Switch the email to current user's email
    email_receiver = posted_user_info[0]["email"]

    # Set up email
    msg = EmailMessage()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['subject'] = subject
    msg.set_content(message)

    context = ssl.create_default_context()

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, msg.as_string())

    # Return to notification page indicating user that the process is complete
    return render_template("notification.html", message="You have successfully confirmed the request! Please contact the registered user with the email address we provided you in your email!", link=previous_page, button_message="Return to Sessions")


# User confirm a session is finished
@app.route("/finished", methods=["POST"])
@login_required
def finished():
    # Get id of the session
    session_id = request.form.get("session_id")

    # Update database
    db.execute("UPDATE sessions SET status = 'finished' WHERE id = (?)", session_id)
    db.execute("UPDATE user_sessions SET relationship = 'posted and finished' WHERE user_id = (?) AND session_id = (?)", session["user_id"], session_id)
    db.execute("UPDATE user_sessions SET relationship = 'registered and finished' WHERE relationship = 'registered' AND session_id = (?)", session_id)

    # Get session info
    session_info = db.execute("SELECT title FROM sessions WHERE id = (?)", session_id)
    
    # Get info of the user who registered this session
    registered_user = db.execute("SELECT username, email FROM users JOIN user_sessions WHERE user_sessions.relationship = 'registered and finished' AND users.id = user_sessions.user_id AND user_sessions.session_id = (?)", session_id)

    # Set up email subject and message
    subject = "Your registered session: " + session_info[0]['title'] + " has finished"
    message = "Hi " + registered_user[0]['username'] + ". One of your registered session just finished. You can still access this session in your history page on our website\nContact Email: " + email_sender

    # Set up receiver email
    email_receiver = registered_user[0]['email']

    # Set up email sender, receiver, subject, and message
    msg = EmailMessage()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['subject'] = subject
    msg.set_content(message)

    context = ssl.create_default_context()

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, msg.as_string())

    # Return to notification page indicating the user the process is complete
    return render_template("notification.html", message="You just confirmed your session: " + session_info[0]['title'] + " is finished!", link="/sessions", button_message="Return to Sessions")


# Change password Page
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    # Use reached route through POST
    if request.method == "POST":
        prev_password = request.form.get("prev_password")

        password = db.execute("SELECT hash FROM users WHERE id = (?)", session["user_id"])

        # make sure users type in their previous password
        if not check_password_hash(password[0]["hash"], prev_password):
            return render_template('notification.html', message="The previous password is incorrect!", link="/change_password", button_message="Return to Change Password")

        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # make sure confirmation matches the new password input
        if new_password != confirmation:
            return render_template('notification.html', message="Confirmation does not match the password", link="/change_password", button_message="Return to Change Password")

        # hash the new password
        new_password = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = (?) WHERE id = (?)", new_password, session["user_id"])

        # Return to homepage
        return redirect("/")

    # User reached route through GET
    else:
        return render_template("change.html")


# History page for finished sessions
@app.route("/history")
def history():
    # Get finished sessions info
    posted_finished_sessions = db.execute("SELECT * FROM sessions WHERE user_id = (?) AND status = 'finished'", session["user_id"])
    registered_finished_sessions = db.execute("SELECT * FROM sessions JOIN user_sessions WHERE user_sessions.user_id = (?) AND relationship = 'registered and finsihed' AND sessions.id = user_sessions.session_id", session["user_id"])

    # Redirect to history page
    return render_template("history.html", posted_finished_sessions=posted_finished_sessions, registered_finished_sessions=registered_finished_sessions)