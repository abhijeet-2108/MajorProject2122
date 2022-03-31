import webbrowser
from urllib.request import urlopen
from time import sleep
while True:
    for i in range(0,50):
        urlopen("http://127.0.0.1:5000/")
        print(i)
    sleep(5)