#!/bin/bash
#this script makes an virtual network interface for the main script and test script to communicate
if_err_exit () {

	if [ $1 -ne 0 ];then
			echo $ERROR_TEMPLATE $command err_code : $1
	fi

}


ERROR_TEMPLATE="failed to"
INTERFACE="$1"
IP_ADDR="$2"
NET_MASK="$3"

if [ $# -ne 3 ];then
		echo  usage : interface_name ip_address netmask 
		exit 1
fi

command="sudo modprobe dummy"
sudo $command
if_err_exit $?

command="ip link add $INTERFACE type dummy"
sudo $command
if_err_exit $?

command="ip addr add $IP_ADDR/$NET_MASK dev $INTERFACE"
sudo $command
if_err_exit $?

command="ifconfig $INTERFACE up"
sudo $command
if_err_exit $?


