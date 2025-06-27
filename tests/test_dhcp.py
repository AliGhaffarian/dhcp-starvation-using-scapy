#!/bin/python3
import sys
import ipaddress
from scapy.all import *
sys.path.append('..')
import dhcp
import random



#test sending packets by sniffing on loopback 
udp_template = IP()/UDP()
dhcp_offer = udp_template/BOOTP(op = 'BOOTREPLY')/DHCP(options = [("message-type", "offer")])
dhcp_request = udp_template/BOOTP(op = 'BOOTREQUEST')/DHCP(options = [("message-type", "request")])


bad_dhcp_list = []

bad_dhcp_list.append(udp_template/dhcp_request[BOOTP]/dhcp_offer[DHCP])
bad_dhcp_list.append(udp_template/dhcp_offer[BOOTP]/dhcp_request[DHCP])

not_dhcp = udp_template/DNS()

for packet in bad_dhcp_list:
    assert dhcp.is_dhcp_offer(packet) == False
    assert dhcp.is_dhcp_ack(packet) == False



assert dhcp.is_dhcp(not_dhcp) == False

bad_pkt_templates= [ \
        IP() / Ether() / UDP(),
        Ether() / IP() / TCP(),
        Ether(),
        IP(),
        UDP(),
        Ether() / UDP() / IP(),
        Ether() / UDP() / IP() / BOOTP(),
        Ether() / UDP() / IP() / BOOTP() / DHCP(),
        DHCP() / Ether() / IP () / UDP()
        ]

for pkt in bad_pkt_templates:
    random_ip = str(
            ipaddress.IPv4Address(random.randint(0, (2 ** 32) - 1))
            )
    err_code = dhcp.starve_ips(
            random_ip,
            str(RandMAC()),
            pkt_to_use=pkt)
    assert err_code == -1
