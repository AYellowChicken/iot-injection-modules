from threading import Thread
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.dot11 import Dot11
from scapy.utils import rdpcap, hexdump
from scapy.all import sendp, sniff
import socket
import numpy
import time

# bind ZEP2 UDP port 17754 ------ conf.dot15d4_protocol = sixlowpan, etc

class Timestamper(Packet):
    name = "Timestamp"
    fields_desc = [
        IEEEFloatField("timestamp", -1)
    ]

result_str = ""

def daemon():
    print("\n\nSniffing initiated ...")
    conf.dot15d4_protocol = "zigbee"

    bind_layers(Ether, Dot15d4)
    bind_layers(IP, Dot15d4)
    bind_layers(Dot11, Dot15d4)
    bind_layers(Ether, Dot15d4FCS)
    bind_layers(IP, Dot15d4FCS)
    bind_layers(Dot11, Dot15d4FCS)
    
    conf.dot15d4_protocol = "zigbee"
    
    global result_str

    while True:
        
        # sniff
        not_sniffed = True
        while not_sniffed:
            p = sniff(iface="enp1s0", count=1) # must sniff with killerbee here... TODO
            if p is not None and len(p) > 0:
                p = p[0]
                print(p.summary())
                if p.haslayer(Ether) and p.src == "42:42:42:42:42:42":
                    print(p.summary())
                    if p.haslayer(Dot15d4):
                        dot15 = p.getlayer(Dot15d4)
                    elif p.haslayer(Dot15d4FCS):
                        dot15 = p.getlayer(Dot15d4FCS)
                    hexdump(dot15)
                    print(dot15.summary())            
                    not_sniffed = False
                    
                    result_str += dot15.summary() + "\n"
                            
        p = dot15
        # append truncated timestamp
        timestamp = str(format(time.time(), '.4f'))
        timestamp = timestamp[3:]
        lay_timestamp = Timestamper(timestamp)
        p /= lay_timestamp
        
        # send on wireless interface
        #p = Ether(src="42:42:42:42:42:42")/p
        p = Ether()/p
        sendp(p, iface="wlp2s0")
    
sniffer_thread = Thread(name="daemon sniffer", target = daemon)
sniffer_thread.setDaemon(True)
sniffer_thread.start()

command = ""
while command != "exit":
    command = input("Enter 'exit' to finish sniffing\n")

text_file = open("sniffedpkts", "w")
text_file.write(result_str)
text_file.close()
