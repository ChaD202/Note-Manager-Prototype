from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
import smtplib
import hashlib
import uuid
import sqlite3
import secrets

app = Flask(__name__)

# adds email server to app config
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='NoteMng@gmail.com',
    MAIL_PASSWORD='FlaskApp74'
)

mail = Mail(app)
app.secret_key = "1234"

# database
db = "NoteMng.db"

# declares static folder
app.static_folder = 'static'

# login functions


def hash_password(password, salt):
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest()


def add_account(database, username, password, email):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex

    hashed_password = hash_password(password, salt)

    connection = sqlite3.connect(database)
    c = connection.cursor()

    # inserts new record into Login database
    c.execute("INSERT INTO Login (Username, Password, Salt, Email) VALUES ('{u}', '{p}', '{s}', '{e}')"
              .format(u=username, p=hashed_password, s=salt, e=email))

    connection.commit()


def check_password(database, username, password):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    try:
        salt = c.execute("SELECT Salt FROM Login WHERE Username == '{u}'".format(u=username)).fetchone()[0]
        real_password = c.execute("SELECT Password FROM Login WHERE Username == '{u}'".format(u=username)).fetchone()[0]

        if hash_password(password, salt) == real_password:
            return True

        else:
            return False

    except TypeError:
        return False


# if password length is <8 or has no A-Z characters or spaces, returns False, otherwise returns True
def password_validate(password):
    if len(password) < 8 or password.find(" ") != -1 or not any(letter.isupper() for letter in password):
        return False

    else:
        return True


# if user exists, return a Boolean value.
def check_user_exists(database, username):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    # creates a list of all the records with the same username. if the list has 0 items, it returns False
    if len(list(c.execute("SELECT * FROM Login WHERE Username = '{u}'".format(u=username)))) == 0:
        return False

    else:
        return True


# token authentication

def create_token(username):
    # The session object is specific to the user and stored in a signed cookie on the user's machine

    # generates a random 16 character hex string which is stored in the users session
    session['{u}_token'.format(u=username)] = secrets.token_hex(16)


def check_for_token(username):
    if '{u}_token'.format(u=username) not in session:
        return False
    else:
        return True


def delete_token(username):
    del session['{u}_token'.format(u=username)]


# email authentication

def send_verification_email(email, username):
    session['verification_token'] = secrets.token_hex(16)
    session['username'] = username

    # creates message instance
    msg = Message("Confirm Email", sender=("NoteMng", "NoteMng@gmail.com"), recipients=[email])

    # creates link to verification token
    link = "http://127.0.0.1:5000/confirm_email/{token}".format(token=session['verification_token'])
    msg.body = "Hello, {name}. Click here to verify your account: {link}".format(name=username, link=link)

    # sends message using mail server
    mail.send(msg)


def verify_account(database, username):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    c.execute("UPDATE Login SET Verified = 'Y' WHERE Username = '{u}'"
              .format(u=username))

    connection.commit()


def check_account_verification(database, username):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    status = c.execute("SELECT Verified FROM Login WHERE Username = '{u}'"
                       .format(u=username)).fetchone()[0]

    connection.close()

    if status == 'Y':
        return True

    else:
        return False


# forgot password

def send_new_password(database, email):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    # generates random password
    password = "A" + secrets.token_hex(8)

    # gets username from database which has the same email
    username = c.execute("SELECT Username FROM Login WHERE Email = '{e}'"
                         .format(e=email)).fetchone()[0]

    connection.close()

    # updates database with new password
    update_password(database, password, username)

    # creates message instance
    msg = Message("New Password", sender=("NoteMng", "NoteMng@gmail.com"), recipients=[email])

    # creates link to verification token
    msg.body = "Hello, {name}. This is your new password: {p}".format(name=username, p=password)

    # sends message using mail server
    mail.send(msg)


def check_email_exists(database, email):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    # creates a list of all the records with the same email. if the list has 0 items, it returns False
    if len(list(c.execute("SELECT * FROM Login WHERE Email = '{e}'".format(e=email)))) == 0:
        return False

    else:
        return True


# note functions

def load_notes(database, username):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    # creates a list of all records in Notes table which matches the username in ascending order
    notes_list = list(c.execute("SELECT * from Notes WHERE Username = '{u}' ORDER BY NoteID ASC"
                                .format(u=username)))

    connection.close()

    return notes_list


# creates 2D array sorted by category from 1D Array of notes and returns it
def sorted_notes(notes_list):
    categories = []

    sorted_list = []

    # for each note in the notes list
    for note in notes_list:
        # if the category of the note isn't already in the notes list, append it to the categories array
        if note[2] not in categories:
            categories.append(note[2])

    # for each category in the categories array
    for category in categories:
        # a specific category list is created
        category_list = []

        # for each note in the notes list
        for note in notes_list:
            # if the note has the same category as the current one from the for loop, append it to the category list
            if note[2] == category:
                category_list.append(note)

        # append this category list to the sorted list
        sorted_list.append(category_list)

    return sorted_list


def add_note(database, username, category, note):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    c.execute("INSERT INTO Notes (Username, Category, Content) VALUES ('{username}', '{category}', '{content}')"
              .format(username=username, category=category, content=note))

    connection.commit()
    connection.close()


def delete_note(database, note_id):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    c.execute("DELETE FROM Notes WHERE NoteID = {id}".
              format(id=note_id))
    connection.commit()


def delete_category(database, category, username):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    c.execute("DELETE FROM Notes WHERE Category = '{c}' AND Username = '{u}'".
              format(c=category, u=username))
    connection.commit()

# settings functions


def check_password_change(database, username, old_password):
    # if old password is correct, return True
    if check_password(database, username, old_password):
        return True

    else:
        return False


def update_password(database, new_password, username):
    connection = sqlite3.connect(database)
    c = connection.cursor()

    # gets salt from database
    salt = c.execute("SELECT Salt FROM Login WHERE Username = '{u}'"
                     .format(u=username)).fetchone()[0]

    # hashes new password with salt
    new_password = hash_password(new_password, salt)

    c.execute("UPDATE Login SET Password = '{p}' WHERE Username = '{u}'"
              .format(p=new_password, u=username))

    connection.commit()
    connection.close()

# login page
@app.route('/', methods=["GET", "POST"])
def login():
    # if data is being sent
    if request.method == "POST":
        # request username and password from form
        username = request.form.get("username")
        password = request.form.get("password")

        # if password is correct and the account has been verified
        if check_password(db, username, password) and check_account_verification(db, username):
            # creates login token stored in the users session
            create_token(username)
            # redirects to note page
            return redirect(url_for("notes", username=username))

        # if password is not correct, show an error
        if not check_password(db, username, password) and username is not None:
            return render_template("login.html", password_error=True)

        # if the account has not been verified
        if not check_account_verification(db, username) and username is not None:
            return render_template("login.html", verification_error=True)

    return render_template("login.html")

# register page
@app.route('/register', methods=["GET", "POST"])
def register():
    # if data is being sent
    if request.method == "POST":
        # request username and password from form
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        # if password hasn't been validated, returns an error
        if not password_validate(password):
            return render_template("register.html", password_error=True)

        # if email has already been used, returns an error
        if check_email_exists(db, email):
            return render_template("register.html", used_email_error=True)

        else:
            # adds account in database, sends verification email and redirects to login page
            try:
                send_verification_email(email, username)
                add_account(db, username, password, email)
                return redirect(url_for("login"))

            # if the unique identifier (username) has been used already, returns error
            except sqlite3.IntegrityError:
                return render_template("register.html", username_error=True)

            # if the email is invalid or does not exist, returns error
            except smtplib.SMTPRecipientsRefused:
                return render_template("register.html", email_error=True)

    return render_template("register.html")

# email confirmation
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        # if token in url is same as token stored in session, verifies username stored in session
        if session['verification_token'] == token:
            verify_account(db, session['username'])

            # deletes verification token and username from session
            del session['verification_token']
            del session['username']

            return render_template("confirm_email.html", verified=True)

        else:
            return render_template("confirm_email.html", verified=False)
    # if no such token is stored in session, return an error
    except KeyError:
        return render_template("confirm_email.html", verified=False)

# forgot password page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        # if the email is not empty and it is in the database, send a new password
        if email is not None and check_email_exists(db, email):
            send_new_password(db, email)

        if not check_email_exists(db, email):
            return render_template("forgot_password.html", email_error=True)

    return render_template("forgot_password.html")

# notes page
@app.route('/notes/<username>', methods=["GET", "POST"])
def notes(username):
    # if user does not exist, or there is no login token in session, return to login page
    if not check_user_exists(db, username) or not check_for_token(username):
        return redirect(url_for("login", error=False))

    # find's users notes then sorts them according to category
    note_list = sorted_notes(load_notes(db, username))

    # if data is being sent
    if request.method == "POST":
        # request username and password from form
        category = request.form.get("category")
        content = request.form.get("note")
        note_id = request.form.get("id")
        category_to_delete = request.form.get("category_to_delete")

        # if there is a value in the category  fields with alphanumeric characters, add to notes
        if category is not None and any(letter.isalpha() for letter in category):
            add_note(db, username, category, content)

        # if there is a value submitted by a delete note button, delete the note
        if note_id is not None:
            delete_note(db, note_id)

        # if there is a value submitted by a delete category button, delete the category
        if category_to_delete is not None:
            delete_category(db, category_to_delete, username)

        # loads sorted list again
        note_list = sorted_notes(load_notes(db, username))
        return render_template("notes.html", username=username, notes=note_list)

    return render_template("notes.html", username=username, notes=note_list)

# settings page
@app.route('/settings/<username>', methods=["GET", "POST"])
def settings(username):
    # if user does not exist, or there is no login token in session, return to login page
    if not check_user_exists(db, username) or not check_for_token(username):
        return redirect(url_for("login"))

    # if data is being sent
    if request.method == "POST":
        # request old and new passwords from form
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")

        if old_password is not None and new_password is not None:
            if check_password(db, username, old_password):
                if password_validate(new_password):
                    # deletes user's login token
                    delete_token(username)
                    # updates account with new password
                    update_password(db, new_password, username)
                    # redirects to login page
                    return redirect(url_for("login"))
                else:
                    return render_template("settings.html", username=username, invalid_pass=True)
            else:
                return render_template("settings.html", username=username, password_error=True)

    return render_template("settings.html", username=username)
