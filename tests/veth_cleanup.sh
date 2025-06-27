#!/bin/bash
#this script makes an virtual network interface for the main script and test script to communicate
if_err_exit () {

	if [ $1 -ne 0 ];then
			echo $ERROR_TEMPLATE $command err_code : $1
			exit $1
	fi
}


ERROR_TEMPLATE="failed to"
INTERFACE="$1"

if [ $# -ne 1 ];then
		echo  usage : $0 interface_name
		exit 1
fi

command="ip link del ${INTERFACE}_1 type veth peer name ${INTERFACE}_2"
$command
if_err_exit $?
