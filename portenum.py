import argparse
import re
from time import sleep
from scapy.all import *

def udpscan(dst_ip,dst_port):
    pkt = sr1(IP(dst=dst_ip)/UDP(sport=5678,dport=dst_port),timeout = 2,verbose = 0)
    if pkt == None:
        print(dst_port, " UDP Open / filtered")
    else:
        if pkt.haslayer(ICMP):
            print(dst_port, " UDP Closed")
        elif pkt.haslayer(UDP):
            print(dst_port, " UDP Open / filtered")
        else:
            print(dst_port, " UDP Unknown")

def tcpscan(dst_ip,dst_port):
    pkt = sr1(IP(dst=dst_ip)/TCP(sport=1234,dport=dst_port,flags="S"),timeout = 1,verbose = 0)
    if pkt != None:
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 20:
                print(dst_port,"close")
            elif pkt[TCP].flags == 18: 
                print(dst_port,"open")
            else:
                print(dst_port,"tcp reset / filtered")
        elif pkt.haslayer(ICMP):
            print(dst_port,"ICMP reset/filtered")
        else:
            print(dst_port,"Unkown port")
    else:
        print(dst_port," TCP Unanswered")
        udpscan(dst_ip=dst_ip,dst_port=dst_port)

parser = argparse.ArgumentParser("Port Scanner")
parser.add_argument("-i","--ip",help="Destination Ip for Scan",required=True)
parser.add_argument("-p","--port",help="Destination Port for Scan",required=True)
args = parser.parse_args()

tempip = args.ip
tempport = args.port
validip = re.findall(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}",tempip)

if len(validip) == 1:
    print("Scanning ",tempip," port " , tempport)
    if "-" not in tempport:
        if len(re.findall(r"\d+",tempport)) > 0:
            tcpscan(tempip,int(tempport))
        else:
            print("please enter port number and port must between 1-65535")
    else:
        temps = re.findall(r"\W",args.port)
        for i in temps:
            if i != "-":
                tempport = args.port.replace(i,"-")
        splitport = tempport.split("-")
        if len(re.findall(r"\d+",splitport[0])) > 0:
            if len(re.findall(r"\d+",splitport[-1])) > 0:
                firstport = int(splitport[0])
                lastport = int(splitport[-1])
                if firstport > 0 and lastport < 65535:
                    for i in range(firstport,lastport):
                        tcpscan(tempip,i)
                        sleep(5)
                else:
                    print("port must between 1-65535")
            else:
                print("please enter valid last port number")
        else:
            print("please enter valid first port number")
else:
    print("please enter valid ip address")
