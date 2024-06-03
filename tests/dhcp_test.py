import sys
sys.path.append('..')

import dhcp
from scapy.all import *




#test sending packets by sniffing on loopback 
udp_template = IP()/UDP()
dhcp_offer = udp_template/BOOTP(op = dhcp.BOOTP_ATTS.OP_CODE.BOOTREPLY)/DHCP(options = [("message-type", "offer")])
dhcp_request = udp_template/BOOTP(op = dhcp.BOOTP_ATTS.OP_CODE.BOOTREQUEST)/DHCP(options = [("message-type", "request")])


bad_dhcp_list = []

bad_dhcp_list.append(udp_template/dhcp_request[BOOTP]/dhcp_offer[DHCP])
bad_dhcp_list.append(udp_template/dhcp_offer[BOOTP]/dhcp_request[DHCP])

not_dhcp = udp_template/DNS()

for packet in bad_dhcp_list:
    assert dhcp.is_dhcp_offer(packet) == False
    assert dhcp.is_dhcp_ack(packet) == False



assert dhcp.is_dhcp(not_dhcp) == False
