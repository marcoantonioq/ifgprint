#!/bin/bash

# 80 WEB
# 111 rpcbind
# 443 WEB SSL
# 631 Cups
# 3306 MySQL
# 22003 SSH

clear;

#!/bin/bash
# Mysql: 
#Password: password

function on(){
	off;

	echo 1 > /proc/sys/net/ipv4/ip_forward
	#echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

	# Teste de redirecionamento
	iptables -t nat -A PREROUTING -s 0.0.0.0/0 -p tcp --dport 8082 -j DNAT --to-destination 10.11.0.24:443
	#iptables -t nat -A PREROUTING -s 0.0.0.0/0 -p tcp --dport 8082 -j DNAT --to-destination 10.11.0.24:443

	#iptables -t nat -A PREROUTING -s 10.11.0.0/16 -p tcp --dport 8081 -j DNAT --to-destination 10.11.0.24:443

	iptables -t nat -A POSTROUTING -j MASQUERADE
	
}

function off(){
	iptables -F
	iptables -X
	iptables -Z
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat -Z
}

case $1 in
	on)
		on
	;;
	off)
		off
	;;
	*)
		echo $"Use: {on|off}" 
		exit 2
esac

iptables -L -n -v
iptables -t nat -L -n -v

exit 0;
