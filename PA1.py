
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, current_app
from flask_mysqldb import MySQL
from wtforms import Form, PasswordField, StringField, TextAreaField, validators, DateField
import flask_login
import os, base64
from functools import wraps
from passlib.hash import sha256_crypt

app = Flask(__name__)

#app.config
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "5799"
app.config["MYSQL_DB"] = "myphotoshare"
#app.config["MYSQL_CURSORCLASS"] = "DictCursor"

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
# Init mysql
mysql = MySQL(app)
with app.app_context():
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT email from Users")
    users = cursor.fetchall()
    print(current_app.name)

def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return test(*args, **kwargs)
        else:
            flash("Log in first!")
            return redirect(url_for('login'))
    return wrap

@app.route('/')
def home():
    return render_template('homepage.html')



class RegForm(Form):
    gender = StringField("Gender", [validators.Length(min = 1, max = 4)])
    email = StringField("EMAIL", [validators.Length(min = 1, max = 30)])
    dob = DateField("Your date of birth (yyyy-mm-dd)")
    fname = StringField("First name", [validators.Length(min = 1, max = 30)])
    lname = StringField("Last name", [validators.Length(min=1, max=30)])
    hometwon = StringField("Hometown", [validators.Length(min = 1, max = 30)])
    password = PasswordField("Password", [
        validators.DataRequired(),
        validators.EqualTo("confirm", message = "password do not match")
    ])
    confirm = PasswordField("confirm password")

class User(flask_login.UserMixin):
    pass

def getUserList():
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT email from Users")
    return cursor.fetchall()

def getIdList():
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT uid from Users")
    return cursor.fetchall()


def getAlbum(aid):
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT pid FROM albumPhoto WHERE aid = '{0}'".format(aid))

    return cursor.fetchall()


def getPhotolist(aid):
    photos = getAlbum(aid)
    photolist = []
    for photo in photos:
        photolist += getPhotos(photo[0])
    return photolist


def getPhotos(pid):
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT imgdata, pid, caption, uid, aid FROM Photos WHERE pid = '{0}'".format(pid))
    photo = cursor.fetchall()

    return photo


def getTags(pid, userid):
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT tid, uid, pid, word FROM photoTags WHERE '{0}' and '{1}'".format(pid, userid))
    Tags = cursor.fetchall()

    return Tags

def getNamebyId(uid):
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT email FROM Users WHERE uid= {0}".format(uid))
    Tags = cursor.fetchone()[0]
    return Tags

@login_manager.user_loader
def user_loader(email):
    users = getUserList()
    if not(email) or email not in str(users):
        return
    user = User()
    user.id = email
    return user

@login_manager.request_loader
def request_loader(request):
    users = getUserList()
    email = request.form.get('email')
    if not(email) or email not in str(users):
        return
    user = User()
    user.id = email
    cursor = mysql.connect().cursor()
    cursor.execute("SELECT password FROM Users WHERE email = '{0}'".format(email))
    data = cursor.fetchall()
    pwd = str(data[0][0] )
    user.is_authenticated = request.form['password'] == pwd
    return user


def getUsersPhotos(uid):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT imgdata, pid, caption, uid, aid FROM Photos WHERE uid = '{0}'".format(uid))
    return cursor.fetchall() #NOTE list of tuples, [(imgdata, pid), ...]

def getUsersAlbums(uid):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT aid, Name, Adate, uid FROM Albums WHERE uid = '{0}'".format(uid))
    return cursor.fetchall()

def getUserIdFromEmail(email):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT uid  FROM Users WHERE email = '{0}'".format(email))
    return cursor.fetchone()[0]

def isEmailUnique(email):
    #use this to check if a email has already been registered
    cursor = mysql.connection.cursor()
    if cursor.execute("SELECT email  FROM Users WHERE email = '{0}'".format(email)):
        #this means there are greater than zero entries with that email
        return False
    else:
        return True


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    if request.method == 'GET':
        email = request.args.get('email')
        password = request.args.get('password')
        print(email, password)
        if email == None:
            return render_template('index.html')

        else:
            cursor = mysql.connect.cursor()
            if cursor.execute("SELECT password FROM Users WHERE email = '{0}'".format(email)):
                data = cursor.fetchall()
                pwd = str(data[0][0])
                if password == pwd:
                    user = User()
                    user.id = email
                    flask_login.login_user(user)  # okay login in user
                    uid = 1
                    cursor = mysql.connect.cursor()
                    cursor.execute("SELECT uid, email FROM Users WHERE uid !='{0}' and uid != '{1}'".format(uid, '1'))
                    userlist = cursor.fetchall()
                    anonymous = True
                    print(anonymous)
                    return render_template('users.html', users=userlist, friends=True, guest=anonymous)
    else:
    '''
    if request.method == 'POST':

        # The request method is POST (page is recieving data)
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connect.cursor()
        # check if email is registered
        if cursor.execute("SELECT password FROM Users WHERE email = '{0}'".format(email)):
            data = cursor.fetchall()
            pwd = str(data[0][0])

            if request.form['password'] == pwd:

                user = User()
                user.id = email
                print(type(user), user.id)
                flask_login.login_user(user)  # okay login in user

                return redirect(url_for('protected'))  # protected is a function defined in this file

        # information did not match
        return "<a href='/index'>Try again</a></br><a href='/register'>or make an account</a>"
    return render_template('index.html')


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return render_template('index.html', message='Logged out')


@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            firstname = request.form.get('firstname')
            lastname = request.form.get('lastname')
            # hometown=request.form.get('hometown')
            # gender=request.form.get('gender')
        except:
            print(
                "couldn't find all tokens")  # this prints to shell, end users will not see this (all print statements go to shell)
            return redirect(url_for('register'))
        cursor = mysql.connect.cursor()
        test = isEmailUnique(email)
        if test:
            print(cursor.execute(
                "INSERT INTO Users (email, password, firstname, lastname) VALUES ('{0}', '{1}', '{2}', '{3}')".format(email, password, firstname, lastname)))
            mysql.connect.commit()
            # log user in
            user = User()
            user.id = email
            flask_login.login_user(user)
            return render_template('profile.html', name=email, message='Account Created!')
        else:
            print("couldn't find all tokens")
            return redirect(url_for('register'))
    else:
        return render_template('index.html', supress='True')


@app.route('/profile')
@flask_login.login_required
def protected():

    return render_template('profile.html', name=flask_login.current_user.id, message="Here's your profile",uid = getUserIdFromEmail(flask_login.current_user.id))

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
@flask_login.login_required
def upload():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True
    if request.method == 'POST':

        aid = request.form.get('aid')
        if aid == None:
            return render_template('profile.html', message="Please create an album to upload photos")
        else:
            uid = getUserIdFromEmail(flask_login.current_user.id)
            imgfile = request.files['photo']
            caption = request.form.get('caption')
            photo_data = base64.standard_b64encode(imgfile.read())
            cursor = mysql.connect.cursor()
            cursor.execute("SELECT count(*) FROM Photos WHERE imgdata = '{0}' and uid='{1}'".format(photo_data, uid))
            checkphoto = cursor.fetchall()
            if checkphoto[0][0]:
                return render_template('profile.html', message="Photo already uploaded")
            else:
                cursor = mysql.connect.cursor()
                cursor.execute(
                    "INSERT INTO Photos (imgdata, caption, uid, aid) VALUES ('{0}', '{1}', '{2}', '{3}' )".format(
                        photo_data, caption, uid, aid))
                mysql.connect.commit()
                cursor = mysql.connect.cursor()
                cursor.execute("SELECT pid FROM photos WHERE imgdata = '{0}'".format(photo_data))
                photoid = cursor.fetchone()[0]
                mysql.connect.commit()
                cursor = mysql.connect.cursor()
                cursor.execute("INSERT INTO albumPhoto (aid, pid) VALUES ('{0}', '{1}' )".format(aid, photoid))
                mysql.connect.commit()

                tags = request.form.get('tags')

                taglist = []
                taglist = tags.split(" ")

                for tag in taglist:
                    cursor = mysql.connect.cursor()
                    cursor.execute(
                        "INSERT INTO photoTags (uid, pid, word) VALUES ('{0}','{1}','{2}')".format(uid, photoid, tag))
                    mysql.connect.commit()

                return render_template('photo.html', name=flask_login.current_user.id, message='Photo uploaded!',
                                       photos=getUsersPhotos(uid))

    # The method is GET so we return a  HTML form to upload the a photo.
    else:
        uid = getUserIdFromEmail(flask_login.current_user.id)
        return render_template('upload.html', albums=getUsersAlbums(uid))


# end photo uploading code

@app.route('/createalbum', methods=['POST', 'GET'])
def createalbum():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    #Name = getNamebyId(uid)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True
    if request.method == 'POST':

        Name = request.form.get('Name')
        cursor = mysql.connect.cursor()
        cursor.execute("INSERT INTO Albums (Name, uid) VALUES ('{0}', '{1}' )".format(Name, uid))
        mysql.connect.commit()

        return render_template('profile.html', name=flask_login.current_user.id, message='Album created!',
                               albums=getUsersAlbums(uid), guest=anonymous)
    else:
        return render_template('createalbum.html')


@app.route("/profile", methods=['GET', 'POST'])
@flask_login.login_required
def profile():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True

    return render_template('profile.html', name=flask_login.current_user.id, message="Here's your profile!",
                           uid=getUserIdFromEmail(flask_login.current_user.id), guest=anonymous)


def active():
    users = getIdList()
    active = []
    count = 0
    for user in users:
        cursor = mysql.connect.cursor()
        cursor.execute("""SELECT count(*) FROM Photos 
                        WHERE uid=%s and uid!=%s
                        """, (user[0], '1'))
        count += cursor.fetchone()[0]

        cursor = mysql.connect.cursor()
        cursor.execute("""SELECT count(*) FROM Comments 
                        WHERE uid=%s and uid!=%s
                        """, (user[0], '1'))
        count += cursor.fetchone()[0]
        if user[0] != 1:
            active += [[count, user[0]]]
    active = sorted(active, reverse=True)

    uids = []
    usercount = 0
    for uid in active:
        usercount += 1
        uids += [uid[1]]
        if usercount > 10:
            break
    return uids


@app.route("/activeUser")
@flask_login.login_required
def activeUser():
    userid = getUserIdFromEmail(flask_login.current_user.id)
    email = flask_login.current_user.id

    global anonymous
    anonymous = False
    friended = False
    if userid == 1:
        anonymous = True
        friended = True
    uids = active()
    userlist = []
    for uid in uids:
        email = getEmailbyid(uid)
        userlist += [[uid, email]]
    return render_template('users.html', users=userlist, friends=friended, guest=anonymous,
                           message="Check active users!", useremail=email)


@app.route("/users", methods=['GET', 'POST'])
@flask_login.login_required
def users():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True

    if request.method == 'GET':
        userid = request.args.get('uid')

        fid = request.args.get('fid')
        selfid = request.args.get('selfid')
        cursor = mysql.connect.cursor()
        cursor.execute("SELECT uid, email FROM Users WHERE uid !='{0}' and uid != '{1}'".format(uid, '1'))
        userlist = cursor.fetchall()
        if userid == None:

            if fid == None:
                if selfid == None:
                    return render_template('users.html', users=userlist, guest=anonymous)
                # Friends
                else:
                    cursor = mysql.connect.cursor()
                    cursor.execute("SELECT fid FROM Friends WHERE uid ='{0}'".format(selfid))
                    friendslist = cursor.fetchall()
                    friendname = []
                    for friend in friendslist:
                        cursor = mysql.connect.cursor()
                        cursor.execute("SELECT uid, email FROM Users WHERE uid ='{0}'".format(friend[0]))
                        friendname += cursor.fetchall()

                    return render_template('users.html', users=friendname, friends=True, guest=anonymous,
                                           message="Your friends!")
            # Friended
            else:
                value = [uid, fid]

                cursor = mysql.connect.cursor()
                cursor.execute("""SELECT count(*)
                                FROM Friends
                                WHERE uid=%s and fid=%s
                                """, value)
                checkfriends = cursor.fetchone()[0]
                if checkfriends:
                    return render_template('users.html', users=userlist, message="You have already been friends!",
                                           friends=False, guest=anonymous)
                else:

                    cursor = mysql.connect.cursor()
                    cursor = mysql.connect.cursor()
                    cursor.execute("INSERT INTO Friends (uid, fid) VALUES ('{0}', '{1}' )".format(uid, fid))
                    mysql.connect.commit()
                    cursor = mysql.connect.cursor()
                    cursor.execute("INSERT INTO Friends (uid, fid) VALUES ('{0}', '{1}' )".format(fid, uid))
                    mysql.connect.commit()
                    return render_template('users.html', users=userlist, message="Added to friends!", friends=False,
                                           guest=anonymous)

        else:
            email = getNamebyId(userid)
            return render_template('albums.html', albums=getUsersAlbums(userid), guest=anonymous,
                                   name=flask_login.current_user.id, homename=email)
    else:
        user = request.form.get('user')
        tags = request.form.get('tags')
        if tags != None:
            taglist = []
            taglist = tags.split(" ")
            for tag in taglist:
                query = "SELECT DISTINCT pid FROM photoTags WHERE word = '{0}'".format(tag)
                cursor = mysql.connect.cursor()
                cursor.execute(query)

        uid = getUserIdFromEmail(flask_login.current_user.id)
        cursor = mysql.connect.cursor()
        cursor.execute("SELECT count(*) FROM Users WHERE email ='{0}'".format(user))
        existed = cursor.fetchone()[0]

        # Can't find the user
        if not existed:
            cursor = mysql.connect.cursor()
            cursor.execute("SELECT uid, email FROM Users WHERE uid !='{0}' and uid != '{1}'".format(uid, '1'))
            userlist = cursor.fetchall()
            return render_template('users.html', users=userlist, friends=True,
                                   message="Cannot find the user! Meets other users!", guest=anonymous)
        # Found!
        else:
            cursor = mysql.connect.cursor()
            cursor.execute("SELECT uid, email FROM Users WHERE email ='{0}'".format(user))
            theuser = cursor.fetchall()
            return render_template('users.html', albums=getUsersAlbums(theuser[0][0]), message=theuser[0][1],
                                   guest=anonymous)


def getTagPhoto(tags):
    taglist = tags

    count = len(taglist)

    pidlist = []
    maxtuple = ()

    for tag in taglist:
        cursor = mysql.connect.cursor()
        cursor.execute("SELECT pid FROM photoTags WHERE word='{0}'".format(tag))
        plist = cursor.fetchall()
        pidlist += plist
        if len(plist) > len(maxtuple):
            maxtuple = plist

    resultpid = []
    for pid in maxtuple:
        for pids in pidlist:
            if pid[0] not in pids:
                continue

        resultpid += pid
    return resultpid


@app.route("/photosearch", methods=['GET', 'POST'])
def photosearch():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True
    if request.method == 'POST':
        tags = request.form.get('tags')
        taglist = tags.split(" ")
        resultpid = getTagPhoto(taglist)
        photolist = []
        for p in resultpid:
            photolist += getPhotos(p)

        return render_template('photo.html', photos=photolist, guest=anonymous, name=flask_login.current_user.id)


@app.route("/recommendation", methods=['GET', 'POST'])
def recommendation():
    uid = getUserIdFromEmail(flask_login.current_user.id)

    if request.method == 'POST':
        tags = request.form.get('tags')
        querytag = tags.split(" ")

        resultpid = getTagPhoto(querytag)

        query1 = ""

        if resultpid == []:
            return render_template('recommendation.html', message="Try other tags!")
        for i in range(len(resultpid)):
            query1 += " or pid=%s"
        query1 = query1[3:]

        query = "SELECT DISTINCT word FROM photoTags WHERE" + query1
        cursor = mysql.connect.cursor()
        cursor.execute(query, resultpid)
        taglist0 = cursor.fetchall()
        taglist = []
        for tag in taglist0:
            if tag[0] not in querytag:
                taglist += tag

        seq = []
        for tag in taglist:
            cursor = mysql.connect.cursor()
            cursor.execute("SELECT count(*) FROM photoTags WHERE word=%s and pid in %s", (tag, resultpid))
            count = cursor.fetchone()[0]
            seq += [(count, tag)]
        seq = sorted(seq, reverse=True)

        return render_template('recommendation.html', sequence=seq)

    else:
        cursor = mysql.connect.cursor()
        cursor.execute("SELECT DISTINCT word FROM photoTags WHERE uid=%s", (uid))
        tags = cursor.fetchall()

        seq = []
        for tag in tags:
            cursor = mysql.connect.cursor()
            cursor.execute("SELECT count(*) FROM photoTags WHERE word=%s and uid=%s", (tag[0], uid))
            count = cursor.fetchone()[0]
            seq += [(count, tag[0])]
        seq = sorted(seq, reverse=True)
        seq = seq[:5]

        pids = []
        resultpid = []
        taglist = []
        for tag in seq:
            taglist += [tag[1]]

        if len(taglist) == 5:
            l1 = rank(getTagPhoto(taglist[:4]))
            l2 = rank(getTagPhoto(taglist[1:]))
            l3 = rank(getTagPhoto(taglist[:3]))
            l4 = rank(getTagPhoto([taglist[0], taglist[2], taglist[3]]))
            l5 = rank(getTagPhoto([taglist[0], taglist[3], taglist[4]]))
            l6 = rank(getTagPhoto([taglist[1], taglist[2], taglist[3]]))
            l7 = rank(getTagPhoto([taglist[1], taglist[3], taglist[4]]))
            l8 = rank(getTagPhoto([taglist[2], taglist[3], taglist[4]]))
            l9 = rank(getTagPhoto(taglist[:2]))
            l10 = rank(getTagPhoto([taglist[0], taglist[2]]))
            l11 = rank(getTagPhoto([taglist[0], taglist[3]]))
            l12 = rank(getTagPhoto([taglist[0], taglist[4]]))
            l13 = rank(getTagPhoto([taglist[1], taglist[2]]))
            l14 = rank(getTagPhoto([taglist[1], taglist[3]]))
            l15 = rank(getTagPhoto([taglist[1], taglist[4]]))
            l16 = rank(getTagPhoto([taglist[2], taglist[3]]))
            l17 = rank(getTagPhoto([taglist[2], taglist[4]]))
            l18 = rank(getTagPhoto([taglist[3], taglist[4]]))
            l19 = rank(getTagPhoto([taglist[0]]))
            l20 = rank(getTagPhoto([taglist[1]]))
            l21 = rank(getTagPhoto([taglist[2]]))
            l22 = rank(getTagPhoto([taglist[3]]))
            l23 = rank(getTagPhoto([taglist[4]]))
            pids = rank(getTagPhoto(
                taglist)) + l1 + l2 + l3 + l4 + l5 + l6 + l7 + l8 + l9 + l10 + l11 + l12 + l13 + l14 + l15 + l16 + l17 + l18 + l19 + l20 + l21 + l22 + l23

        if len(taglist) == 4:
            l1 = rank(getTagPhoto(taglist[:3]))
            l2 = rank(getTagPhoto(taglist[1:]))
            l3 = rank(getTagPhoto(taglist[:2]))
            l4 = rank(getTagPhoto([taglist[0], taglist[2]]))
            l5 = rank(getTagPhoto([taglist[0], taglist[3]]))
            l6 = rank(getTagPhoto([taglist[1], taglist[2]]))
            l7 = rank(getTagPhoto([taglist[1], taglist[3]]))
            l8 = rank(getTagPhoto([taglist[2], taglist[3]]))
            l9 = rank(getTagPhoto([taglist[0]]))
            l10 = rank(getTagPhoto([taglist[1]]))
            l11 = rank(getTagPhoto([taglist[2]]))
            l12 = rank(getTagPhoto([taglist[3]]))
            pids = rank(getTagPhoto(taglist)) + l1 + l2 + l3 + l4 + l5 + l6 + l7 + l8 + l9 + l10 + l11 + l12

        if len(taglist) == 3:
            l1 = rank(getTagPhoto(taglist[:2]))
            l2 = rank(getTagPhoto([taglist[0], taglist[2]]))
            l3 = rank(getTagPhoto([taglist[1], taglist[2]]))
            l4 = rank(getTagPhoto([taglist[0]]))
            l5 = rank(getTagPhoto([taglist[1]]))
            l6 = rank(getTagPhoto([taglist[2]]))
            pids = rank(getTagPhoto(taglist)) + l2 + l3 + l1 + l4 + l5 + l6
            '''+rank(getTagPhoto(taglist[:2]))+rank(getTagPhoto([taglist[0],taglist[2]]))
            +rank(getTagPhoto([taglist[1],taglist[2]]))
            +rank(getTagPhoto([taglist[0]]))+rank(getTagPhoto([taglist[1]]))+rank(getTagPhoto([taglist[2]]))'''

        if len(taglist) == 2:
            l1 = rank(getTagPhoto([taglist[0]]))
            l2 = rank(getTagPhoto([taglist[1]]))
            pids = rank(getTagPhoto(taglist)) + l1 + l2

        if len(taglist) == 1:
            pids = rank(getTagPhoto(taglist))
        for pid in pids:
            if pid not in resultpid:
                resultpid += [pid]
        photolist = []
        for rpid in resultpid:
            photolist += getPhotos(rpid)
        return render_template('recommendation.html', photos=photolist)


def rank(pids):
    seq = []
    for pid in pids:
        cursor = mysql.connect.cursor()
        cursor.execute("SELECT count(*) FROM photoTags WHERE pid = %s", (pid))
        count = cursor.fetchone()[0]
        seq += [[count, pid]]
    seq = sorted(seq)
    resultpid = []
    for s in seq:
        resultpid += [s[1]]

    return resultpid


@app.route("/photo", methods=['GET', 'POST'])
@flask_login.login_required
def photo():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True

    print(anonymous)
    if request.method == 'GET':
        pid = request.args.get('pid')

        photouid = request.args.get('photouid')
        if pid == None:
            uid = getUserIdFromEmail(flask_login.current_user.id)
            return render_template('photo.html', photos=getUsersPhotos(uid), message="Here's your photos!",
                                   albums=getUsersAlbums(uid), guest=anonymous, name=flask_login.current_user.id)
        else:
            userid = request.args.get('userid')
            usertagid = request.args.get('usertagid')
            word = request.args.get('word')
            # list comments

            cursor = mysql.connect.cursor()
            cursor.execute("SELECT uid, email, content FROM Comments WHERE pid = '{0}'".format(pid))
            commentlist = cursor.fetchall()
            # Search tag
            if word != None:
                # Search one person's tag
                if usertagid != None:
                    cursor = mysql.connect.cursor()
                    cursor.execute("""SELECT pid
                                FROM photoTags
                                WHERE uid=%s and word=%s
                                """, (usertagid, word))
                    photolist = []
                    pids = cursor.fetchall()

                    for pid in pids:
                        photolist += getPhotos(pid[0])
                    return render_template('photo.html', photos=photolist, guest=anonymous,
                                           name=flask_login.current_user.id)
                # World tag search
                else:
                    cursor = mysql.connect.cursor()
                    cursor.execute("""SELECT pid
                                FROM photoTags
                                WHERE word=%s
                                """, (word))
                    photolist = []
                    pids = cursor.fetchall()

                    for pid in pids:
                        photolist += getPhotos(pid[0])
                    return render_template('photo.html', photos=photolist, guest=anonymous,
                                           name=flask_login.current_user.id)
            # No tag search
            else:

                if userid == None:

                    return render_template('photo.html', photo=getPhotos(pid), tags=getTags(pid, photouid),
                                           likes=getlikes(pid), count=likescount(pid), comments=commentlist,
                                           guest=anonymous, name=flask_login.current_user.id)
                # Like photo
                else:
                    cursor = mysql.connect.cursor()
                    cursor.execute("""SELECT count(*)
                                    FROM Likes
                                    WHERE pid=%s and uid=%s
                                    """, (pid, uid))
                    checklike = cursor.fetchall()
                    if checklike[0][0]:
                        return render_template('photo.html', photo=getPhotos(pid), tags=getTags(pid, userid),
                                               likes=getlikes(pid), count=likescount(pid),
                                               message="You have liked this photo", comments=commentlist,
                                               guest=anonymous, name=flask_login.current_user.id)
                    else:
                        cursor = mysql.connect.cursor()
                        cursor.execute("""SELECT email
                                    FROM Users
                                    WHERE uid=%s
                                    """, (uid))
                        useremail = cursor.fetchone()[0]
                        cursor = mysql.connect.cursor()
                        cursor.execute(
                            "INSERT INTO Likes (uid, email, pid)VALUES ('{0}', '{1}','{2}' )".format(uid, useremail,
                                                                                                     pid))
                        mysql.connect.commit()
                        return render_template('photo.html', photo=getPhotos(pid), tags=getTags(pid, userid),
                                               likes=getlikes(pid), count=likescount(pid), message="Liked the photo!",
                                               comments=commentlist, guest=anonymous, name=flask_login.current_user.id)
    else:
        comment = request.form.get('comment')
        pid = request.form.get('pid')
        print(pid)
        photouid = request.form.get('photouid')

        uid = getUserIdFromEmail(flask_login.current_user.id)

        cursor = mysql.connect.cursor()
        cursor.execute("SELECT uid FROM Photos WHERE pid = '{0}'".format(pid))
        puid = cursor.fetchone()[0]

        if puid == uid:

            cursor = mysql.connect.cursor()
            cursor.execute("SELECT uid, email, content FROM Comments WHERE pid = '{0}'".format(pid))
            commentlist = cursor.fetchall()
            return render_template('photo.html', photo=getPhotos(pid), tags=getTags(pid, photouid), likes=getlikes(pid),
                                   comments=commentlist, message="Cannot comment your own photos", guest=anonymous,
                                   name=flask_login.current_user.id)
        else:

            email = getEmailbyid(uid)
            cursor = mysql.connect.cursor()
            cursor.execute("""INSERT INTO Comments (photouid, pid, content, uid, email) 
                            VALUES ('{0}', '{1}','{2}', '{3}', '{4}')""".format(photouid, pid, comment, uid, email))
            mysql.connect.commit()

            cursor = mysql.connect.cursor()
            cursor.execute("SELECT uid, email, content FROM Comments WHERE pid = '{0}'".format(pid))
            commentlist = cursor.fetchall()
            return render_template('photo.html', photo=getPhotos(pid), tags=getTags(pid, photouid), likes=getlikes(pid),
                                   comments=commentlist, guest=anonymous, name=flask_login.current_user.id)


def getEmailbyid(uid):
    cursor = mysql.connect.cursor()
    cursor.execute("SELECT email FROM Users WHERE uid = '{0}'".format(uid))
    email = cursor.fetchone()[0]
    return email


def getlikes(pid):
    cursor = mysql.connect.cursor()
    cursor.execute("""SELECT uid, email, pid
                    FROM Likes
                    WHERE pid=%s
                    """, (pid))
    return cursor.fetchall()


def likescount(pid):
    likes = getlikes(pid)
    count = 0
    for i in likes:
        count += 1
    return count


@app.route("/albums", methods=['GET', 'POST'])
@flask_login.login_required
def albums():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True

    if request.method == 'GET':
        userid = request.args.get('userid')
        aid = request.args.get('aid')
        if aid == None:

            return render_template('albums.html', albums=getUsersAlbums(uid), guest=anonymous,
                                   name=flask_login.current_user.id)
        else:
            if userid != None:
                email = getEmailbyid(userid)
                return render_template('albums.html', albums=getUsersAlbums(userid), guest=anonymous,
                                       name=flask_login.current_user.id, homename=email)
            else:

                photolist = getPhotolist(aid)

                return render_template('photo.html', photos=photolist, guest=anonymous,
                                       name=flask_login.current_user.id)


@app.route("/delete", methods=['GET'])
@flask_login.login_required
def delete():
    uid = getUserIdFromEmail(flask_login.current_user.id)
    global anonymous
    anonymous = False
    if uid == 1:
        anonymous = True
    aid = request.args.get('aid')
    pid = request.args.get('pid')
    uid = getUserIdFromEmail(flask_login.current_user.id)
    photouid = request.args.get('photouid')
    photouid = int(photouid)
    # Cannot delete others' item

    if uid != photouid:
        if pid == None:
            return render_template('albums.html', albums=getUsersAlbums(photouid), message="No permission!",
                                   guest=anonymous, name=flask_login.current_user.id)

        else:

            aid = int(aid)

            return render_template('photo.html', photos=getPhotolist(aid), message="No permission!", guest=anonymous,
                                   name=flask_login.current_user.id)
    else:
        if pid == None:
            cursor = mysql.connect.cursor()
            cursor.execute("DELETE FROM Albums WHERE aid = '{0}'".format(aid))
            mysql.connect.commit()
            return render_template('albums.html', albums=getUsersAlbums(uid), message="Album deleted!", guest=anonymous,
                                   name=flask_login.current_user.id)
        else:

            cursor = mysql.connect.cursor()

            cursor.execute("DELETE FROM Photos WHERE pid = '{0}'".format(pid))
            mysql.connect.commit()

            return render_template('photo.html', photos=getPhotolist(aid), message="Photo deleted!", guest=anonymous,
                                   name=flask_login.current_user.id)


if __name__ == '__main__':
    app.secret_key = "nmsl!"
    app.run(debug=True)
