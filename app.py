import argon2
from flask import Flask, render_template, session, url_for
from flask import copy_current_request_context, redirect
from flask_sqlalchemy import SQLAlchemy, request
from datetime import datetime
from argon2 import *
from argon2 import PasswordHasher
from flask_wtf import FlaskForm
from sqlalchemy import true, desc
from wtforms import StringField, PasswordField, DateField
from wtforms.validators import InputRequired, Length
from flask_bootstrap import Bootstrap
from flask_login import current_user
from flask_login import LoginManager, UserMixin, current_user, login_manager
from flask_login import logout_user, login_required, login_user
from wtforms.fields import DateField, EmailField
from datetime import datetime
from sqlalchemy.orm import relationship
import os
import requests


app = Flask(__name__)
Bootstrap(app)


app.config['SECRET_KEY'] = 'kfsiojofonsndfosdfohijkoefjkoijdofoijhsaoih'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_BINDS'] = {
    'comments': 'sqlite:///com.db',
    'Uploads': 'sqlite:///uploads.db',
    'User': 'sqlite:///user.db',
    'comments':'sqlite:///comments.db'}

login_manager = LoginManager()
login_manager.init_app(app)


db = SQLAlchemy(app)


UPLOAD_FOLDER=r"C:\Users\neleb\OneDrive\Радна површина\flask_blog\upload"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config["Debug"]=True
app.config['MAIL_SERVER']='smtp.mailgun.org'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'postmaster@sandbox4b7e7a3f7c7f4c8d9f8512f5863970c5.mailgun.org'
app.config['MAIL_PASSWORD'] = '8b336a39d52d6d8c8dc0de00393105ec-fe066263-89751b1b'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config["MAIL_MAX_EMAILS"]=None
app.config["MAIL_SUPPRESS_SEND"]= False
app.config["MAIL_ASCII_ATTACHMENTS"] = False
app.config["MAIL_DEFAULT_SENDER"]='postmaster@sandbox4b7e7a3f7c7f4c8d9f8512f5863970c5.mailgun.org'


class Blogpost(db.Model):
    __tablename__="blog"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(72), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    date_posted = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)
    pinn = db.Column(db.Boolean, default=False)
    htmlrender = db.Column(db.Boolean, default=False)
    comment = relationship("Comments", cascade="all, delete")
    like=relationship("Like", cascade="all, delete")
    uid = db.Column(db.Integer, db.ForeignKey("user.uid"), nullable=False)

    def __repr__(self):
        return 'Blog post' + str(self.id)



class Like(db.Model, UserMixin):
    __tablename__="like"
    lid= db.Column(db.Integer, primary_key=True)
    likestatus = db.Column(db.Boolean, default=False, nullable=False)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    blogid = db.Column(db.Integer, db.ForeignKey("blog.id"), nullable=True)
    uuid = db.Column(db.Integer, db.ForeignKey("user.uid"), nullable=True)



class User(db.Model, UserMixin):
    __tablename__ = 'user'
    uid = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(72), nullable=False)
    sname = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    birth = db.Column(db.DateTime, nullable=False)
    date_registrated = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)
    cnic = db.Column(db.String(13), default=False)
    image = relationship("Images")
    autid = relationship("Blogpost")
    role = db.Column(db.Boolean, default=False)

    def is_authenticated(self):
        return self.authenticated

    def get_id(self):
        # returns the user e-mail
        return self.uid

    def is_anonymous(self):
        return False

    @login_manager.user_loader
    def load_user(self):
        return User.query.filter_by(uid=self).first()


class Comments(db.Model, UserMixin):
    __tablename__="comments"
    cid = db.Column(db.Integer, primary_key=True)
    ccontent = db.Column(db.Text, nullable=False)
    cauthor = db.Column(db.Text, nullable=False)
    blogid = db.Column(db.Integer, db.ForeignKey("blog.id"), nullable=False)


class Images(db.Model, UserMixin):
    __tablename__="images"
    iid= db.Column(db.Integer, primary_key=True)
    filename= db.Column(db.Text, nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey("user.uid"), nullable=False)



@app.route('/')
def pr():
    return redirect(url_for("create_post"))


@app.route('/create/post', methods= ["POST", "GET"])
def create_post():
    if request.method=='POST':
        title = request.form["title"]
        content = request.form["content"]
        htmlrender = request.form.get("htmlrender")
        if htmlrender=="checked":
            htmlrender=True
        else:
            htmlrender=False
        author = current_user.get_id()
        author= current_user.fname
        new_post= Blogpost(title=title, content=content, author=author, htmlrender=htmlrender, uid= current_user.uid )
        db.session.add(new_post)
        db.session.commit()

        return redirect('/create/post')
    else:
        post=Blogpost.query.filter_by(pinn=True).order_by(desc(Blogpost.date_posted)).all()
        posts=Blogpost.query.filter_by(pinn=False).order_by(desc(Blogpost.date_posted)).all()
        return render_template("posts.html", post=post, posts=posts)


@app.route("/post/like/<int:id>", methods = ["GET", "POST"])
def like(id):
    if request.method=="POST":
        checklike = Like.query.filter_by(blogid=id, uuid=current_user.uid).first()
        if checklike!=None and checklike.likestatus == True:
            checklike.likestatus = False
            db.session.commit()
            return redirect(url_for("open", id=id))
        elif checklike!=None and checklike.likestatus==False:
            checklike.likestatus = True
            db.session.commit()
            return redirect(url_for("open", id=id))
        elif checklike==None:
            like = True
            author = current_user.fname
            makelike = Like(likestatus=like, author=author, blogid=id, uuid=current_user.uid)
            db.session.add(makelike)
            db.session.commit()
            return redirect(url_for("open", id=id))
        else:
            return "Error 404"
        


@app.route("/create/comment/<int:id>", methods=["GET", "POST"])
def create_com(id):
    if request.method=="POST":
        comment=request.form["comment"]
        author=current_user.fname
        makecomment=Comments(ccontent=comment, cauthor=author, blogid=id)
        db.session.add(makecomment)
        db.session.commit()
        return redirect(url_for("open", id=id))
    else:
        comments = Comments.query.filter_by(blogid=id).all()
        return render_template("post.html", comments=comments)


@app.route("/posts/stick/<int:id>", methods=["GET", "POST"])
def stick(id):
    post=Blogpost.query.filter_by(id=id).first()
    if post.pinn==True:
        post.pinn=False
        db.session.commit()
    else:
        post.pinn=True
        db.session.commit()
    return redirect('/create/post')


    
@app.route("/post/open/<int:id>")
def open(id):
    post = Blogpost.query.get_or_404(id)
    creator = User.query.filter_by(uid = post.uid).first()
    comments = Comments.query.filter_by(blogid=id)
    count_likes= Like.query.filter_by(blogid=id, likestatus=True)
    return render_template("post.html", post=post, comments=comments, count_likes=count_likes, creator=creator)





@app.route('/posts/delete/<int:id>')
def delete(id):
        post = Blogpost.query.get(id)
        delete_likes = Like.query.filter_by(blogid=post.id).all()
        for o in delete_likes:
            db.session.delete(o)
        delete_comments = Comments.query.filter_by(blogid=post.id).all()
        for i in delete_comments:
            db.session.delete(i)
        db.session.delete(post)
        db.session.commit()
        return redirect('/create/post')
#    except(UnmappedClassError, UnmappedInstanceError):
#            return redirect('/create/post')


@app.route("/posts/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    post = Blogpost.query.get_or_404(id)

    if request.method == "POST":
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        return redirect('/create/post')
    else:
        return render_template('edit.html', post=post)



class LoginForm(FlaskForm):
    email = EmailField(
        'email',
        validators=[InputRequired(
            "Username is reuired"),
            Length(
                    min=4,
                    max=30,
                    message='Name must be longer than 4 and shorter than 30')])
    password = PasswordField(
        'password',
        validators=[InputRequired(
            'Password is required'),
            Length(
                min=8,
                max=32,
                message='Pw must be longer than 8 chars and less than 32')])



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route("/uploads")
@login_required
def uploads():
    return render_template("upload.html")


class registratee(FlaskForm):
    fname = StringField(
        'First Name:',
        validators=[InputRequired(
            "Username is reuired"),
            Length(
                    min=3,
                    max=30,
                    message='First name must be longer than 4 and shorter than 30')])
    sname = StringField(
        'Second Name:',
        validators=[InputRequired(
            "Username is reuired"),
            Length(
                    min=3,
                    max=30,
                    message='Second name must be longer than 4 and shorter than 30')])
    email = EmailField(
        'Email:',
        validators=[InputRequired(
            "Email is reuired")])
    password = PasswordField(
        'Password:',
        validators=[InputRequired(
            'Password is required'),
            Length(
                min=8,
                max=32,
                message='Password must be longer than 8 chars and less than 32')])
    birth = DateField('Date of birth', format='%Y-%m-%d')
    cnic = StringField(
        'CNIC:',
        validators=[InputRequired(
            "CNIC is reuired"),
            Length(
                    min=13,
                    max=13,
                    message='Please input CNIC')])


@app.route("/user/registrate", methods=["GET", "POST"])
def reg():
    if current_user.is_authenticated:
        return redirect('/create/post')
    elif request.method == 'POST':
        registrate = registratee()
        fname = request.form['fname']
        sname = request.form['sname']
        email = request.form["email"]
        password = request.form["password"]
        birth = request.form["birth"]
        cnic = request.form["cnic"]
        s= User.query.filter_by(email=email, cnic = cnic).first()
        if s:
            return render_template("error.html")
        else:
            ph = PasswordHasher()
            hashs = ph.hash(password)
            new_user = User(
                fname=fname,
                sname=sname,
                email=email,
                password=hashs,
                birth=datetime.strptime(birth, "%Y-%m-%d").date(),
                cnic=cnic)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("indexx"))
    else:
        registrate = registratee()
        return render_template('registrate.html', form=registrate)


@app.route("/user/list", methods=["GET", "POST"])
@login_required
def lis():
    posts = User.query.all()
    return render_template("userlist.html", posts=posts)


@app.route('/login', methods=['POST', 'GET'])
def indexx():
    form = LoginForm()
    if form.validate_on_submit():
        ph = PasswordHasher()
        email = form.email.data
        pasword = form.password.data
        user = User.query.filter_by(email=email).first()
        try:
            if user and ph.verify(user.password, pasword):
                login_user(user, remember=True)
                return redirect('/create/post')
            else:
                return 'Error in Login'
        except argon2.exceptions.VerifyMismatchError:
            return "Error, please try again"
    else:
        return render_template('login.html', form=form)


@app.route('/profile/', methods=['POST', 'GET'])
@login_required
def profile():
    if current_user:
        query = User.query.filter_by(uid=current_user.uid).first()
        hisposts = Blogpost.query.filter_by(uid=query.uid).all()

        return render_template("profile.html", query=query, hisposts=hisposts)
    else:
        redirect("/login")



@app.route('/profilee/<int:id>', methods=['POST', 'GET'])
@login_required
def profilee(id):
    qwery = Blogpost.query.filter_by(id=id).first()
    query = User.query.filter_by(uid=qwery.uid).first()
    hisposts = Blogpost.query.filter_by(uid=query.uid).all()
    return render_template("profile.html", query=query, hisposts=hisposts)
 


@app.route('/edit_profile', methods=['POST', 'GET'])
@login_required
def editprofile():

    if current_user:
        query = User.query.filter_by(uid=current_user.uid).first()

        registrate = registratee(obj=query)
        if request.method == 'POST':
            query = User.query.filter_by(uid=current_user.uid).first()

            ffname = request.form['fname']
            ssname = request.form['sname']
            eemail = request.form["email"]
            bbirth = request.form["birth"]
            ccnic = request.form["cnic"]
            query.fname = ffname
            query.sname = ssname
            query.email = eemail
            query.birth = datetime.strptime(bbirth, "%Y-%m-%d").date()
            query.cnic = ccnic
            db.session.commit()
            return redirect("/profile")
        else:
            query = User.query.filter_by(uid=current_user.uid).first()
            return render_template("editprofile.html", form=registrate)
    else:
        redirect("/login")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def changpw():
    if request.method == "POST":
        query = User.query.filter_by(uid=current_user.uid).first()
        oldpw = request.form["oldpw"]
        newpw = request.form["newpw"]
        confpw = request.form["confpw"]
        ph = PasswordHasher()
        try:
            if ph.verify(query.password, oldpw):
                if newpw != confpw:
                    return "Greška, šifre se ne podudaraju"
                else:
                    query.password = ph.hash(newpw)
                    db.session.commit()
                    return redirect("/")
            else:
                return "Greska"
        except argon2.exceptions.VerifyMismatchError:
            return "Error, please try again"
    else:
        return render_template("pwreset.html")



if __name__ == '__main__':
    app.run(debug=True)
