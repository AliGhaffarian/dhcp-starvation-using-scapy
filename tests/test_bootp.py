#!/bin/python3
import sys

sys.path.append('..')
import dhcp


from scapy.all import *

bootp_packet = Ether()/IP()/UDP()/BOOTP()
bad_dhcp_packet = Ether()/IP()/UDP()/DHCP()

assert dhcp.is_bootp(bootp_packet) == True
assert dhcp.is_bootp(bad_dhcp_packet) == False

bootp_reply = Ether()/IP()/UDP()/BOOTP(op = 2)
bootp_request = Ether()/IP()/UDP()/BOOTP(op = 1)

assert dhcp.is_bootp_reply(bootp_reply) == True
assert dhcp.is_bootp_reply(bad_dhcp_packet) == False

assert dhcp.is_bootp_reply(bootp_request) == False
assert dhcp.is_bootp_reply(bad_dhcp_packet) == False

