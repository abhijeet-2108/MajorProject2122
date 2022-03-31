from scapy.all import *
import os
import time
import csv
import pandas as pd
from time import sleep
while True:
    
    pkts = sniff(count=50,filter="host 192.168.66.240")

    dic = []
    dic2 = []
    dt_string = time.strftime("%Y-%m-%d_%H-%M-%S")
    # with open("static/netlogs/"+dt_string+".txt".format(dt_string),'a') as f:
    for pkt in pkts:
        temp = pkt.sprintf("%IP.dst%",)
        temp2 = pkt.sprintf("%IP.src%",)
        dic.append(temp)
        dic2.append(temp2)
    info_dict = {
        "TimeStamp":dt_string,
        "Dst_IP":dic,
        "Source_IP":dic2,
    }
    df = pd.DataFrame.from_dict(info_dict)
    df.to_csv("static/netlogs/"+dt_string+".csv",header=True,index=False)
    print("Network Scheduler is alive!")
    print(dt_string)
    sleep(1)

# def network_monitor():
# pkts = sniff(count=1,filter="port 5000 and host 127.0.0.1",iface="lo")

    # network_monitor()