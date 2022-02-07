from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap
import os
import time
import random
from flask import Response
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib import pyplot as plt
from matplotlib.figure import Figure
from flask import render_template
import io
import re
import base64
import csv

email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
# iris = pd.read_csv("Iris.csv")
# iris2 = sns.load_dataset('iris')


# filepath = os.path.join(os.path.dirname(__file__),'iris.csv')

# open_read = open(filepath,'r')
# page =''

# while True:
#     read_data = open_read.readline()
#     page += '<p>%s</p>' % read_data
#     if open_read.readline() == '':
#         break
# dataset = tablib.Dataset()
# with open(os.path.join(os.path.dirname(__file__),'iris.csv')) as f:
#     dataset.csv = f.read()
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask

def sensor():
    """ Function for test purposes. """
    dt_string = time.strftime("%Y-%m-%d_%H-%M-%S")
    cmd = 'top -b -n 3 | sed -n '3, 6{s/^ *//;s/ *$//;s/  */,/gp;};6q' >>templates/trust-repository/data-information/logs/'+dt_string+'.txt'
    os.system(cmd)
    field_names = ['%Cpu(s)','Memory']
    dict ={}
    with open("templates/trust-repository/data-information/logs/"+dt_string+".txt".format(dt_string), 'a') as f:
      texts = f.readlines()
      count = 0
      for text in texts:
        count += 1
        text2=text.split(',')
        if (text2[0] == '%Cpu(s):'):
          dict['%Cpu(s)']=text2[1]
        elif (text2[1] == 'Mem'):
          dict['Memory']=text2[12]
    print(dict)
    with open("templates/trust-repository/data-information/logs/"+dt_string+".csv".format(dt_string), 'w') as f:
        w = csv.DictWriter(f, dict.keys())
        w.writeheader()
        w.writerow(dict)
    os.remove("templates/trust-repository/data-information/logs/"+dt_string+".txt")
#     with open("templates/trust-repository/data-information/logs/"+dt_string+".txt".format(dt_string), 'a') as out_file:

#          out_file.write("test"+dt_string)
    print("Scheduler is alive!")
    print(dt_string)

sched = BackgroundScheduler(daemon=True)
sched.add_job(sensor,'interval',minutes=1)
sched.start()

app=Flask(__name__)
app.config['SECRET_KEY'] = "key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/majorproject2122'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), unique = True, nullable=False)
    email_id = db.Column(db.String(100), unique = True, nullable=False)
    password = db.Column(db.String(100),nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    email_id = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Email Id"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exits. Please choose a different username")
    def validate_email_id(self, email_id):
            existing_user_email_id = User.query.filter_by(email_id=email_id.data).first()
            if existing_user_email_id:
                raise ValidationError("That Email id already exits. Please choose a different Email id")

class LoginForm(FlaskForm):
    email_id = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Email Id"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

@app.route('/')

def index():
    if current_user.is_authenticated:
        user = current_user.username
        return render_template("index.html", user = user)
    else:
        return render_template("index.html")

@app.route('/login', methods = ['GET', 'POST'])

def login():
    form=LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email_id=form.email_id.data).first()
        if user:
            if bcrypt.check_password_hash(user.password , form.password.data):
                login_user(user)
                return redirect(url_for('index'))

    return render_template("login.html", form= form)
@app.route('/register', methods = ['GET', 'POST'])

def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,email_id=form.email_id.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template("register.html",form= form)

@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_authenticated:
            user = current_user.username
            return render_template("dashboard.html", user = user)
    else:
        return render_template("dashboard.html")
@app.route('/trustrepository', methods = ['GET', 'POST'])
@login_required
def trustrepository():
    if current_user.is_authenticated:
        user = current_user.username
        return render_template("/trust-repository/index.html", user = user)
    else:
        return render_template("/trust-repository/index.html")

def logged_user():
    return current_user.is_authenticated
app.jinja_env.globals.update(logged_user = logged_user)

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('login')



if __name__ == "__main__":
    app.run(debug=True)
















# def plotView():
#     fig = Figure()
#     axis = fig.add_subplot(1, 1, 1)
#     axis.set_title("title")
#     axis.set_xlabel("x-axis")
#     axis.set_ylabel("y-axis")
#     axis.grid()
#     axis.plot(iris.Id, iris["SepalLengthCm"], "r--")
    
#     pngImage = io.BytesIO()
#     FigureCanvas(fig).print_png(pngImage)
    
#     pngImageB64String = "data:image/png;base64,"
#     pngImageB64String += base64.b64encode(pngImage.getvalue()).decode('utf8')
    
#     data = dataset.html

#     #return render_template("index.html", image=pngImageB64String, data=data)
#     return render_template("index.html", image=pngImageB64String, data=data)
# @app.route('/plot.png')
# def plot_png():
#     fig = create_figure()
#     output = io.BytesIO()
#     FigureCanvas(fig).print_png(output)
#     return Response(output.getvalue(), mimetype='image/png')

# def create_figure():
#     fig = Figure()
#     axis = fig.add_subplot(1, 1, 1)
#     xs = iris["Id"]
#     ys = iris["SepalLengthCm"]
#     axis.plot(xs, ys,'ro')
#     return fig

# @app.route("/plot2.png")
# def plot2_png():
#     fig = create2_figure()
#     output = io.BytesIO()
#     FigureCanvas(fig).print_png(output)
#     return Response(output.getvalue(), mimetype='image/png')

# def create2_figure():
#     fig = Figure()
#     axis = fig.add_subplot(1, 1, 1)
#     xs = iris["PetalLengthCm"]
#     ys = iris["SepalLengthCm"]
#     axis.plot(xs, ys,'bo')
#     return fig


