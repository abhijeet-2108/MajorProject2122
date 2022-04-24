from scapy.all import *
import os
import time
import csv
import pandas as pd
from time import sleep
import requests
import xml.etree.ElementTree as et
import pyshark
import csv
from scapy.all import *

import pprint

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import csv
import seaborn as sns; sns.set()

from keras.models import Sequential, load_model
from keras.layers import Dense, LSTM, Bidirectional
#from keras.utils import plot_model
from keras.utils.vis_utils import plot_model
from keras.utils.np_utils import to_categorical
from keras.utils import np_utils

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import confusion_matrix

import nest_asyncio
from sklearn.metrics import accuracy_score
model = load_model("brnn_model.h5")
features=[ 'frame.len', 'ip.hdr_len',
       'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
       'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
       'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
       'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
       'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
       'tcp.time_delta']

while True:
    
    # pkts = sniff(count=50,filter="host 192.168.66.240")
    pkts = sniff(count=50)

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
    
    wrpcap("static/netlogs/"+dt_string+".pcap", pkts)
    xml_list = []
    packet_list = []
    tag = "normal"
    headings = ["frame.encap_type","frame.len","frame.protocols","ip.hdr_len","ip.len"\
                ,"ip.flags.rb","ip.flags.df","p.flags.mf","ip.frag_offset","ip.ttl",\
                "ip.proto","ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.len",\
                "tcp.ack","tcp.flags.res","tcp.flags.ns","tcp.flags.cwr","tcp.flags.ecn",\
                "tcp.flags.urg","tcp.flags.ack","tcp.flags.push","tcp.flags.reset",\
                "tcp.flags.syn","tcp.flags.fin","tcp.window_size","tcp.time_delta","class"]
    packet_list.append(headings)
    nest_asyncio.apply()
    for packet in cap:
        temp = []
        temp.append(str(packet.frame_info._all_fields["frame.encap_type"]) )#0
        temp.append(str(packet.frame_info._all_fields["frame.len"])) #1
        temp.append(str(packet.frame_info._all_fields["frame.protocols"])) #2
        if hasattr(packet, 'ip'):
            temp.append(str(packet.ip._all_fields['ip.hdr_len']))#3
            temp.append(str(packet.ip._all_fields['ip.len']))#4
            temp.append(str(packet.ip._all_fields['ip.flags.rb']))#5
            temp.append(str(packet.ip._all_fields['ip.flags.df']))#6
            temp.append(str(packet.ip._all_fields['ip.flags.mf']))#7
            temp.append(str(packet.ip._all_fields['ip.frag_offset']))#8
            temp.append(str(packet.ip._all_fields['ip.ttl']))#9
            temp.append(str(packet.ip._all_fields['ip.proto']))#10
            temp.append(str(packet.ip._all_fields['ip.src']))#11
            temp.append(str(packet.ip._all_fields['ip.dst']))#12
        else:
            temp.extend(["0","0","0","0","0","0","0","0","0","0"])
        if hasattr(packet, 'tcp'):
            temp.append(str(packet.tcp._all_fields['tcp.srcport']))#13
            temp.append(str(packet.tcp._all_fields['tcp.dstport']))#14
            temp.append(str(packet.tcp._all_fields['tcp.len']))#15
            temp.append(str(packet.tcp._all_fields['tcp.ack']))#16
            temp.append(str(packet.tcp._all_fields['tcp.flags.res']))#17
            temp.append(str(packet.tcp._all_fields['tcp.flags.ns']))#18
            temp.append(str(packet.tcp._all_fields['tcp.flags.cwr']))#19
            temp.append(str(packet.tcp._all_fields['tcp.flags.ecn']))#20
            temp.append(str(packet.tcp._all_fields['tcp.flags.urg']))#21
            temp.append(str(packet.tcp._all_fields['tcp.flags.ack']))#22
            temp.append(str(packet.tcp._all_fields['tcp.flags.push']))#23
            temp.append(str(packet.tcp._all_fields['tcp.flags.reset']))#24
            temp.append(str(packet.tcp._all_fields['tcp.flags.syn']))#25
            temp.append(str(packet.tcp._all_fields['tcp.flags.fin']))#26
            temp.append(str(packet.tcp._all_fields['tcp.window_size']))#27
            #temp.append(packet.tcp._all_fields['tcp.analysis.bytes_in_flight'])
            #temp.append(packet.tcp._all_fields['tcp.analysis.push_bytes_sent'])
            temp.append(str(packet.tcp._all_fields['tcp.time_delta']))#28
        else:
            temp.extend(["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0",])
        temp.append(tag)
        print(temp)
        packet_list.append(temp)
    with open("static/pcaplogs/"+dt_string+".csv", 'w+') as writeFile:
        writer = csv.writer(writeFile)
        writer.writerows(packet_list)
    os.remove("static/netlogs/"+dt_string+".pcap")
    data_normal = pd.read_csv("static/pcaplogs/"+dt_string+".csv")


    data_normal.columns=['frame.encap_type','frame.len', 'frame.protocols', 'ip.hdr_len',
        'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
        'ip.ttl', 'ip.proto', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
        'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
        'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
        'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
        'tcp.time_delta','class']
    data_normal=data_normal.drop(['frame.encap_type','frame.protocols','ip.src', 'ip.dst'],axis=1)

    X_test=data_normal
    X_normal= data_normal[features].values
    Y_normal= data_normal['class']
    Y=Y_normal
    for i in range(0,len(Y)):
        if Y[i] =="attack":
            Y[i]=0
        else:
            Y[i]=1
    scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
    scalar.fit(X_normal)
    X_normal = scalar.transform(X_normal)
    X = X_normal
    features2 = len(X[0])
    samples = X.shape[0]
    train_len = 25
    input_len = samples - train_len
    I = np.zeros((samples - train_len, train_len, features2))

    for i in range(input_len):
        temp = np.zeros((train_len, features2))
        for j in range(i, i + train_len - 1):
            temp[j-i] = X[j]
        I[i] = temp
    X_train, X_test, Y_train, Y_test = train_test_split(I, Y[25:100000], test_size = 0.2)

    predict = model.predict(X_test, verbose=1)

    predictn2 = predict.flatten()

    for i in range(len(predictn2)):
    if not predictn2[i] < 0.4:
        predictn2[i] = 1.0;
    else:
        predictn2[i] = 0.0;

    print(predictn2)
    predictn2 = predictn2.tolist()
    print(predictn2)
    predictn2 = [int(X) for X in predictn2]
    print(predictn2)
    trust2 = 100 * accuracy_score(list(Y_test),predictn2)
    print(trust2)

    print("Network Scheduler is alive!")
    print(dt_string)
    sleep(1)

# def network_monitor():
# pkts = sniff(count=1,filter="port 5000 and host 127.0.0.1",iface="lo")

    # network_monitor()