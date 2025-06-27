from scapy.all import *

import logging
import logging.config
import colorlog
import sys

# Define the format and log colors
log_format = '%(asctime)s [%(levelname)s] %(name)s [%(funcName)s]: %(message)s'
log_colors = {
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
        }

# Create the ColoredFormatter object
console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s' + log_format,
        log_colors = log_colors
        )

FILENAME = os.path.basename(__file__).split('.')[0]

logger = logging.getLogger(FILENAME)
logger.setLevel(logging.DEBUG)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(console_formatter)
stdout_handler.setLevel(logging.INFO)

logger.addHandler(stdout_handler)


def sendp_icmp(src_ip : str, src_mac : str, dst_ip : str, dst_mac : str, interface : str = conf.iface):
    
    packet = Ether(dst = dst_mac, src = src_mac , type='IPv4')\
            / IP(src = src_ip, dst = dst_ip)\
            / ICMP()
    logger.debug(f"sending {packet} to {dst_ip},{dst_mac} via {interface}")
    
    sendp(packet, iface=interface)

def keep_ips_alive_icmp(devices : list[tuple[str,str]], dhcp_server_ip : str, dhcp_server_mac : str):
    logger.info(f"keeping alive these ips : {devices}")
    
    for device in devices:
        sendp_icmp(dst_ip=dhcp_server_ip, dst_mac=dhcp_server_mac,src_ip=device[0], src_mac=device[1], interface=device[2])

