#!/bin/python3
import subprocess
import sys
import ipaddress
import scapy.all
sys.path.append('..')
import dhcp

KEA_DHCP4_CONFIG_PATH='/etc/kea/kea-dhcp4.conf'
KEA_DHCP4_CONFIG_BACKUP_PATH='/etc/kea/kea-dhcp4.conf.bak'

#configs
KEA_DHCP4_TEST_CONFIG_PATH='./kea-dhcp4.conf'
VETH_PAIR_PREFIX='p'
TEST_SUBNET=ipaddress.IPv4Network('192.0.2.0/24') #kea default subnet
IPS_TO_STARVE=3

#global vars derived from configs (don't touch)
DHCP_SERVER_VETH_NAME=f'{VETH_PAIR_PREFIX}_2'
ATTACKER_VETH_NAME=f'{VETH_PAIR_PREFIX}_1'
DHCP_SERVER_INTERFACE_IP=TEST_SUBNET[1]

dhcp.args.sniff_interface = ATTACKER_VETH_NAME

WAS_DHCP_SERVER_RUNNING_BEFORE_TESTING=0
def config_and_run_dhcp_server():
    global WAS_DHCP_SERVER_RUNNING_BEFORE_TESTING

    err_code = subprocess.call(
            ['systemctl', 'is-active','quiet', 'kea-dhcp4-server.service'],
            )
    WAS_DHCP_SERVER_RUNNING_BEFORE_TESTING = 1 if err_code == 0 else 0

    subprocess.run(
            ['mv', KEA_DHCP4_CONFIG_PATH, KEA_DHCP4_CONFIG_BACKUP_PATH],
            check=True
            )
    subprocess.run(
            ['cp', KEA_DHCP4_TEST_CONFIG_PATH, KEA_DHCP4_CONFIG_PATH],
            check=True
            )

    #run the dhcp server
    subprocess.run(
            ['systemctl', 'restart', 'kea-dhcp4-server.service'], 
            check=True
            )


    subprocess.run(
            ['systemctl', 'is-active','quiet', 'kea-dhcp4-server.service'],
            check=True
            )

def restore_dhcp_server_config():
    subprocess.run(
            ['cp', KEA_DHCP4_CONFIG_BACKUP_PATH, KEA_DHCP4_CONFIG_PATH],
            check=True
            )

    #run the dhcp server
    subprocess.run(
            ['systemctl', 'restart', 'kea-dhcp4-server.service'], 
            check=True
            )
def init_veth():
    #usage : interface_name ip_address netmask
    subprocess.run(
            ['bash', 'veth_init.sh', str(VETH_PAIR_PREFIX), str(DHCP_SERVER_INTERFACE_IP), str(TEST_SUBNET.netmask)],
            check=True 
            )

def cleanup_veth():
    subprocess.run(
            ['bash', 'veth_cleanup.sh', str(VETH_PAIR_PREFIX)],
            check=True
            )
    
    if WAS_DHCP_SERVER_RUNNING_BEFORE_TESTING:
        subprocess.run(
                ['systemctl', 'restart', 'kea-dhcp4-server.service'], 
                check=True
                )

init_funcs = [init_veth, config_and_run_dhcp_server]
cleanup_funcs = [cleanup_veth, restore_dhcp_server_config]
if __name__ == "__main__":
    dhcp.conf.verb = False

    print('initing')
    for func in init_funcs:
        func()

    scapy.all.conf.ifaces.reload()
    server_mac = scapy.all.conf.ifaces[DHCP_SERVER_VETH_NAME].mac

    print('starving ips from test dhcp server')
    occupied_ips = dhcp.starve_ips(
            server_ip = str(DHCP_SERVER_INTERFACE_IP), 
            server_mac = server_mac,
            interface = ATTACKER_VETH_NAME,
            sniff_interface = ATTACKER_VETH_NAME,
            ips_to_starve = IPS_TO_STARVE
            )

    assert len(occupied_ips) == IPS_TO_STARVE
    for dhcp_entry in occupied_ips:
        current_occupied_ip = ipaddress.IPv4Address(dhcp_entry[0])
        assert current_occupied_ip in TEST_SUBNET, f"{current_occupied_ip=} not in TEST_SUBNET"

    print('passed')
    print('cleaning up')
    for func in cleanup_funcs:
        func()


