import argparse
from scapy.all import *

def tcpscan(dst_ip,dst_port):
    print("Scanning ",dst_ip," port " , dst_port)
    pkt = sr1(IP(dst=dst_ip)/TCP(sport=4567,dport=dst_port,flags="S"),timeout = 1,verbose = 0)
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
        print(dst_port,"Unanswered")

parser = argparse.ArgumentParser("Port Scanner")
parser.add_argument("-ip","--ip",help="Destination Ip for Scan",required=True);
parser.add_argument("-port","--port",help="Destination Port for Scan",required=True);

args = parser.parse_args()
tcpscan(args.ip,int(args.port))