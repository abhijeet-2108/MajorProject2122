from flask import Flask, render_template, url_for, redirect,session,request
from flask_session import Session
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
import pandas as pd
import numpy as np
import functools
##
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
import datetime
import psutil as ps
from scapy.all import *

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
def net_usage(inf = "enp0s3"):   #change the inf variable according to the interface
    net_stat = ps.net_io_counters(pernic=True, nowrap=True)[inf]
    net_in_1 = net_stat.bytes_recv
    net_out_1 = net_stat.bytes_sent
    packet_in_1 = net_stat.packets_recv
    packet_out_1 = net_stat.packets_sent
    
    time.sleep(1)
    net_stat = ps.net_io_counters(pernic=True, nowrap=True)[inf]
    net_in_2 = net_stat.bytes_recv
    net_out_2 = net_stat.bytes_sent
    packet_in_2 = net_stat.packets_recv
    packet_out_2 = net_stat.packets_sent

    net_in = round((net_in_2 - net_in_1) , 3)
    net_out = round((net_out_2 - net_out_1) , 3)
    packet_in = round((packet_in_2 - packet_in_1) , 3)
    packet_out = round((packet_out_2 - packet_out_1) , 3)
    return net_in,net_out,packet_in,packet_out
    # print(f"Current net-usage:\nIN: {net_in} MB/s, OUT: {net_out} MB/s")


def sensor():
    
    # cmd = "top -b -n 3 | sed -n '3, 6{s/^ *//;s/ *$//;s/  */,/gp;};6q' >>templates/trust-repository/data-information/logs/"+dt_string+".txt"
    # os.system(cmd)
    # field_names = ['%Cpu(s)','Memory']
    # dict ={}
    # with open("templates/trust-repository/data-information/logs/"+dt_string+".txt".format(dt_string), 'r') as f:
    #   texts = f.readlines()
    #   count = 0
    #   for text in texts:
    #     count += 1
    #     text2=text.split(',')
    #     if (text2[0] == '%Cpu(s):'):
    #       dict['%Cpu(s)']=text2[1]
    #     elif (text2[1] == 'Mem'):
    #       dict['Memory']=text2[12]
    # print(dict)
    # with open("templates/trust-repository/data-information/logs/"+dt_string+".csv".format(dt_string), 'w') as f:
    #     w = csv.DictWriter(f, dict.keys())
    #     w.writeheader()
    #     w.writerow(dict)
    # os.remove("templates/trust-repository/data-information/logs/"+dt_string+".txt")
    dt_string = time.strftime("%Y-%m-%d_%H-%M-%S")
    # time_today = str(datetime.datetime.now())
    with open("static/logs/"+dt_string+".csv".format(dt_string), 'a') as file:
    # with open('VM_INFO'+time_today+'.csv', 'a') as file:
        writer = csv.writer(file)
        writer.writerow(
            ['date','time','cpu_load', 'idle_time_cpu', 'kernal_process_time_cpu', 'normal_process_time_usermode_cpu', 'freq_max', 'freq_min',
             'disk_usage_total', 'disk_usage_used', 'disk_usage_free', 'disk_usage_in_percent', 'disk_reading_count',
             'disk_writing_count', 'disk_reading_bytes', 'disk_writing_bytes','net_in','net_out','packet_in','packet_out'])
        for i in range(1):
            date = time.strftime('%d-%m-%Y')
            now = time.strftime('%H:%M:%S')
            idle_time_cpu = ps.cpu_times().idle
            kernal_process_time_cpu = ps.cpu_times().system
            normal_process_time_usermode_cpu = ps.cpu_times().user
            # iowait_time_cpu = ps.cpu_times_percent().iowait
            freq_max = ps.cpu_freq().max
            freq_min = ps.cpu_freq().current
            disk_usage_total = ((ps.disk_usage('/').total) // (2 ** 10))
            disk_usage_used = ((ps.disk_usage('/').used) // (2 ** 10))
            disk_usage_free = ((ps.disk_usage('/').free) // (2 ** 10))
            disk_usage_in_percent = ps.disk_usage('/').percent
            disk_reading_count = ps.disk_io_counters(perdisk=False).read_count
            disk_writing_count = ps.disk_io_counters(perdisk=False).write_count
            disk_reading_bytes = ps.disk_io_counters(perdisk=False).read_bytes
            disk_writing_bytes = ps.disk_io_counters(perdisk=False).write_bytes
            net_in,net_out,packet_in,packet_out = net_usage()
            cpu_load2 = ps.cpu_percent(1)
            cpu_load = float(cpu_load2)
            writer.writerow(
                [date,now, cpu_load, idle_time_cpu, kernal_process_time_cpu, normal_process_time_usermode_cpu, freq_max, freq_min,
                 disk_usage_total, disk_usage_used, disk_usage_free, disk_usage_in_percent, disk_reading_count,
                 disk_writing_count, disk_reading_bytes, disk_writing_bytes, net_in, net_out, packet_in, packet_out])

    print("Scheduler is alive!")
    print(dt_string)
    file_list = os.listdir("static/logs/")
    mystring = 'static/logs/'
    file_list = [mystring + s for s in file_list]
    def without_csv(csv):
        csv2 = []
        for i in csv:
            if i.endswith('.csv') and not i.startswith('combined'):
                csv2.append(i)
        return csv2
    file_list = without_csv(file_list)
    def last_chars(x):
        return(x[-20:])
    
    # def network_monitor():
    #     # pkts = sniff(count=1,filter="port 5000 and host 127.0.0.1",iface="lo")
    #     pkts = sniff(count=1,filter="port 5000",iface="lo")

    #     dic = []
    #     dic2 = []
    #     dt_string = time.strftime("%Y-%m-%d_%H-%M-%S")
    #     # with open("static/netlogs/"+dt_string+".txt".format(dt_string),'a') as f:
    #     for pkt in pkts:
    #         temp = pkt.sprintf("%IP.dst%",)
    #         temp2 = pkt.sprintf("%IP.src%",)
    #         dic.append(temp)
    #         dic2.append(temp2)
    #     info_dict = {
    #         "TimeStamp":dt_string,
    #         "Dst_IP":dic,
    #         "Source_IP":dic2,
    #     }
    #     df = pd.DataFrame.from_dict(info_dict)
    #     df.to_csv("static/netlogs/"+dt_string+".csv",header=True,index=False)
    #     print("Network Scheduler is alive!")
    #     print(dt_string)
    # network_monitor()



    ##
    # plt.figure(figsize=(10,5))
    # plt.plot(x,data['Memory'],color='blue', marker='o',markerfacecolor='green',markersize=2)
    # plt.ylabel('Memory Usage')
    # plt.title('Memory Usage Graph')
    # plt.savefig('static/image/monitoring/memory_plot.png', format='png')
    # plt.close()

sched = BackgroundScheduler({'apscheduler.timezone': 'UTC'},daemon=True)
# sched.add_job(network_monitor,'interval',minutes=1)
sched.add_job(sensor,'interval',minutes=1)
sched.start()

app=Flask(__name__)
app.config['SECRET_KEY'] = "key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Majorproject2122.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)



db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def load_all_user():
    return User.query.all()

def load_user_ip():
    ip = request.environ.get('HTTP_X_REAL_IP',request.remote_addr)
    return ip

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
    if session.get('name') == None:
        return redirect(url_for(app.login))


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
                session['name'] = user.username
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
        session['name'] = form.username.data
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


@app.route('/trustrepository/datainformation/log', methods = ['GET', 'POST'])
@login_required
    

def trustrepository_datainformation_log():
    dt_string = time.strftime("%Y-%m-%d_%H-%M-%S")
    file_list = os.listdir("static/logs/")
    # mystring = 'templates/trust-repository/data-information/logs/'
    # file_list = [mystring + s for s in file_list]
    def without_csv(csv):
        csv2 = []
        for i in csv:
            if i.endswith('.csv') and not i.startswith('combined'):
                csv2.append(i[:-4])
        return csv2
    def last_chars(x):
        return(x[-20:])
    
    file_list = without_csv(file_list)
    # file_list = sorted(file_list,key = last_chars)
    
    f_l = pd.DataFrame(file_list)
    f_l[0] = pd.to_datetime(f_l[0],format='%Y-%m-%d_%H-%M-%S')
    from datetime import date, timedelta

    gr = f_l.groupby(pd.Grouper(key=0, freq='W'))

    grouped_date = {}

    for name, group in gr:
        grouped_date[name - timedelta(7)] = list(group[0])
    # pprint(grouped_date)
    #
    #html code
    # <!--  {%for i in range(0,len)%} -->
    #   <!-- <div class="d-flex"> -->
    #     <!-- <li>{{file_list[i]}}<button class="btn btn-secondary testbtn"  onclick="testfunction()" id="btn_for_value">Download file</button></li> -->
    #     <!-- 2022-02-22_12-18-14 -->
        



    #   <!-- </div> -->
    #   <!-- {%endfor%} --> 
    if current_user.is_authenticated:
        user = current_user.username
        return render_template("trust-repository/data-information/logs/index.html", user = user, file_list=file_list,len=len(file_list),grouped_date=grouped_date)
    else:
        return render_template("trust-repository/data-information/logs/index.html",file_list=file_list,len=len(file_list),grouped_date=grouped_date)
# file_list=file_list,len=len(file_list),
    # if current_user.is_authenticated:
    #         user = current_user.username
    #         return render_template("trust-repository/data-information/logs/index.html", user = user)
    # else:
    #     return render_template("trust-repository/data-information/logs/index.html")
    

@app.route('/trustrepository/datainformation/monitoring', methods = ['GET', 'POST'])
@login_required
def trustrepository_datainformation_monitoring():
    # file_list = os.listdir("templates/trust-repository/data-information/logs/")
    
    # mystring = 'templates/trust-repository/data-information/logs/'
    
    # file_list = [mystring + s for s in file_list]

    # def without_csv(csv):
    #     csv2 = []
    #     for i in csv:
    #         if i.endswith('.csv') and not i.startswith('combined'):
    #             csv2.append(i)
    #     return csv2
    # file_list = without_csv(file_list)
    # def last_chars(x):
    #     return(x[-20:])
    
    # combined_csv = pd.concat([pd.read_csv(f) for f in sorted(file_list, key = last_chars)])
    # combined_csv.to_csv("templates/trust-repository/data-information/logs/combined_csv.csv", index=False)

    # data = pd.read_csv('templates/trust-repository/data-information/logs/combined_csv.csv')
    
    # fig = plt.figure()
    # x = np.arange(start=1,stop=1+len(data['Memory']))
    # plt.plot(x,data['%Cpu(s)'],color='blue', marker='o',markerfacecolor='green',markersize=2)
    # plt.ylabel('Cpu % Usage')
    # plt.title('Cpu Usage Graph')
    # plt.savefig('static/image/monitoring/cpu_plot.png', format='png')
    # plt.close()
    # ##
    # plt.figure()
    # plt.plot(x,data['Memory'],color='blue', marker='o',markerfacecolor='green',markersize=2)
    # plt.ylabel('Memory Usage')
    # plt.title('Memory Usage Graph')
    # plt.savefig('static/image/monitoring/memory_plot.png', format='png')
    # plt.close()
    
    # os.remove('templates/trust-repository/data-information/logs/combined_csv.csv')
    file_list = os.listdir("static/logs/")
    mystring = 'static/logs/'
    file_list = [mystring + s for s in file_list]
    def without_csv(csv):
        csv2 = []
        for i in csv:
            if i.endswith('.csv') and not i.startswith('combined'):
                csv2.append(i)
        return csv2
    file_list = without_csv(file_list)
    def last_chars(x):
        return(x[-20:])
    def graphs():
        combined_csv = pd.concat([pd.read_csv(f) for f in sorted(file_list, key = last_chars)])
        combined_csv.to_csv("static/logs/combined_csv.csv", index=False)

        data = pd.read_csv('static/logs/combined_csv.csv')
        
        fig = plt.figure(figsize=(10,5))
        x = np.arange(start=1,stop=1+len(data['cpu_load']))
        plt.plot(x,data['cpu_load'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('Cpu % Usage')
        plt.title('Cpu Usage Graph')
        plt.savefig('static/image/monitoring/cpu_load.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['idle_time_cpu'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('idle_time_cpu')
        plt.title('idle_time_cpu Graph')
        plt.savefig('static/image/monitoring/idle_time_cpu_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['kernal_process_time_cpu'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('kernal_process_time_cpu')
        plt.title('kernal_process_time_cpu Graph')
        plt.savefig('static/image/monitoring/kernal_process_time_cpu_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['normal_process_time_usermode_cpu'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('normal_process_time_usermode_cpu')
        plt.title('normal_process_time_usermode_cpu Graph')
        plt.savefig('static/image/monitoring/normal_process_time_usermode_cpu_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['freq_max'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('freq_max')
        plt.title('freq_max Graph')
        plt.savefig('static/image/monitoring/freq_max_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['freq_min'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('freq_current')
        plt.title('freq_current Graph')
        plt.savefig('static/image/monitoring/freq_min_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_usage_total'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_usage_total')
        plt.title('disk_usage_total Graph')
        plt.savefig('static/image/monitoring/disk_usage_total_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_usage_used'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_usage_used')
        plt.title('disk_usage_used Graph')
        plt.savefig('static/image/monitoring/disk_usage_used_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_usage_free'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_usage_free')
        plt.title('disk_usage_free Graph')
        plt.savefig('static/image/monitoring/disk_usage_free_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_usage_in_percent'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_usage_in_percent')
        plt.title('disk_usage_in_percent Graph')
        plt.savefig('static/image/monitoring/disk_usage_in_percent_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_reading_count'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_usage_in_percent')
        plt.title('disk_reading_count Graph')
        plt.savefig('static/image/monitoring/disk_reading_count_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_writing_count'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_writing_count')
        plt.title('disk_writing_count Graph')
        plt.savefig('static/image/monitoring/disk_writing_count_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_reading_bytes'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('disk_reading_bytes')
        plt.title('disk_reading_bytes Graph')
        plt.savefig('static/image/monitoring/disk_reading_bytes_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['disk_writing_bytes'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        # print(type(data['date']))
        # plt.xticks(x)
        plt.ylabel('disk_writing_bytes')
        plt.title('disk_writing_bytes Graph')
        plt.savefig('static/image/monitoring/disk_writing_bytes_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['net_in'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('net_in')
        plt.title('network_in Graph')
        plt.savefig('static/image/monitoring/net_in_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['net_out'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('net_out')
        plt.title('network_out Graph')
        plt.savefig('static/image/monitoring/net_out_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['packet_in'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('packet_in')
        plt.title('packet_in Graph')
        plt.savefig('static/image/monitoring/packet_in_plot.png', format='png')
        plt.close()
        plt.figure(figsize=(10,5))
        plt.plot(x,data['packet_out'],color='blue', marker='o',markerfacecolor='green',markersize=2)
        plt.ylabel('packet_out')
        plt.title('packet_out Graph')
        plt.savefig('static/image/monitoring/packet_out_plot.png', format='png')
        plt.close()
        
        os.remove('static/logs/combined_csv.csv')
    graphs()
    
    

    if current_user.is_authenticated:
        user = current_user.username
        return render_template("/trust-repository/data-information/monitoring/index.html", user = user)
    else:
        return render_template("/trust-repository/data-information/monitoring/index.html")
    

@app.route('/trustrepository/datainformation/database_activity', methods = ['GET', 'POST'])
@login_required
def trustrepository_datainformation_database_activity():
    
    users = load_all_user()
    ip = load_user_ip()
    text = ''
    with open('static/trust.txt') as f:
        text = f.read()
    if current_user.is_authenticated:
        user = current_user.username
        return render_template("/trust-repository/data-information/database_activity/index.html", user = user,users = users, ip= ip,text = text)
    else:
        return render_template("/trust-repository/data-information/database_activity/index.html")
    

@app.route('/trustrepository', methods = ['GET', 'POST'])
@login_required
def trustrepository():
    if current_user.is_authenticated:
        user = current_user.username
        return render_template("/trust-repository/index.html", user = user)
    else:
        return render_template("/trust-repository/index.html")

# @app.route('/trustrepository/', methods = ['GET', 'POST'])
# @login_required
# def trustrepository():
#     if current_user.is_authenticated:
#         user = current_user.username
#         return render_template("/trust-repository/index.html", user = user)
#     else:
#         return render_template("/trust-repository/index.html")

def logged_user():
    return current_user.is_authenticated
app.jinja_env.globals.update(logged_user = logged_user)

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('login')


# if __name__ == "__main__":
#     app.run(host="192.168.66.240",debug=True,port=5001)

if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=True,port=80)
















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


