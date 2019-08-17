from flask import Flask, render_template, request, redirect, url_for, session
import hashlib
import uuid
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = "1234"

db = "NoteMng.db"

# declares static folder
app.static_folder = 'static'

# login functions


def hash_password(password, salt):
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest()


def save_password(database, username, password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex

    hashed_password = hash_password(password, salt)

    connection = sqlite3.connect(database)
    c = connection.cursor()

    c.execute("INSERT INTO Login (Username, Password, Salt) VALUES ('{u}', '{p}', '{s}')"
              .format(u=username, p=hashed_password, s=salt))

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
    if len(list(c.execute("SELECT * from Login WHERE Username = '{u}'".format(u=username)))) == 0:
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
    global db

    # if data is being sent
    if request.method == "POST":
        # request username and password from form
        username = request.form.get("username")
        password = request.form.get("password")

        # if password is correct
        if check_password(db, username, password):
            # creates login token stored in the users session
            create_token(username)
            # redirects to note page
            return redirect(url_for("notes", username=username))

        # if password is not correct, show an error
        if not check_password(db, username, password) and username != "":
            return render_template("login.html", error=True)

    return render_template("login.html", error=False)

# register page
@app.route('/register', methods=["GET", "POST"])
def register():
    global db

    # if data is being sent
    if request.method == "POST":
        # request username and password from form
        username = request.form.get("username")
        password = request.form.get("password")

        # if password hasn't been validated
        if not password_validate(password):
            return render_template("register.html", username_error=False, password_error=True)

        else:
            # saves password in database and redirects to login page
            try:
                save_password(db, username, password)
                return redirect(url_for("login", error=False))

            # if database is locked or the unique identifier (username) has been used already, returns error
            except sqlite3.IntegrityError:
                return render_template("register.html", username_error=True)

    return render_template("register.html", username_error=False, password_error=False)

# notes page
@app.route('/notes/<username>', methods=["GET", "POST"])
def notes(username):
    global db

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

        # if there is a value in the category and content fields, add to notes
        if category is not None and content is not None:
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
    global db

    # if user does not exist, or there is no login token in session, return to login page
    if not check_user_exists(db, username) or not check_for_token(username):
        return redirect(url_for("login", error=False))

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
                    return render_template("settings.html", username=username, password_error=False, invalid_pass=True)
            else:
                return render_template("settings.html", username=username, password_error=True, invalid_pass=False)

    return render_template("settings.html", username=username, password_error=False, invalid_pass=False)
