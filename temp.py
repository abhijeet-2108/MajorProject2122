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
import pandas as pd
import numpy as np
import functools
##
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
import datetime
import psutil as ps
from scapy.all import *

from pylab import *
from numpy import NaN
import webbrowser
from urllib.request import urlopen
from time import sleep
while True:
    def m(a):
        z = 0
        for n in range(1, 100):
            z = z**2 + a
            if abs(z) > 2:
                return n
        return NaN

        
    for i in range(0,50):
        # urlopen("http://192.168.66.240")
        print(i)


    X = arange(-2, .5, .002)
    Y = arange(-1,  1, .002)
    Z = zeros((len(Y), len(X)))
    
    for iy, y in enumerate(Y):
        print (iy, "of", len(Y))
        for ix, x in enumerate(X):
            Z[iy,ix] = m(x + 1j * y)
    
    imshow(Z, cmap = plt.cm.prism, interpolation = 'none', extent = (X.min(), X.max(), Y.min(), Y.max()))
    xlabel("Re(c)")
    ylabel("Im(c)")
    savefig('static/image/mandelbrot_python.svg', format='svg')
    show()
    
    sleep(5)
