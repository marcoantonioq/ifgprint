#!/bin/bash

# 80 WEB
# 111 rpcbind
# 443 WEB SSL
# 631 Cups
# 3306 MySQL
# 22003 SSH

########################################­###
# Variaveis
########################################­###
declare -A PORTAS;
declare -A LAN_TCP;
declare -A LAN_UDP;

IP="10.11.0.3"
REDE="10.11.0.0/16"
IF_ETH="ens34"
IF_LAN1="vlan1"


IPT=$(which iptables);
SYSCTL="/sbin/sysctl"

########################################­###
# Rules default
########################################­###
function rules_default(){
	$IPT -P INPUT $1;
	$IPT -P OUTPUT $1;
	$IPT -P FORWARD $1;

	## permitir loopback
	$IPT -A INPUT -i lo -j ACCEPT
	$IPT -A OUTPUT -o lo -j ACCEPT


	# $IPT -A INPUT -i $IF_ETH -j DROP
}

function rules_clear(){	
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t filter -F
	iptables -X # cadeias customizadas
	iptables -t nat -Z # Zera os contadores das cadeias
	iptables -t mangle -Z 
	iptables -t filter -Z
}

## Carregar modulos
####################
function modules(){
	modprobe ip_conntrack
	modprobe ip_conntrack_ftp
	modprobe ip_conntrack_ftp;
	modprobe ip_nat_ftp
	modprobe ip_nat_ftp;
	modprobe ip_tables
	modprobe ipt_LOG
	modprobe ipt_MASQUERADE
	modprobe ipt_REJECT
	modprobe iptable_filter
	modprobe nf_conntrack_ipv4
}


#######################
## Função do Kernel
#######################

function kernel()
{
	echo $1 > /proc/sys/net/ipv4/ip_forward;
}

########################################­###
# Firewall
########################################­###


############
# stateless
############
function rules(){

	## registar e negar pacotes inválidos
	$IPT -A INPUT -m state --state INVALID -j LOG --log-prefix "INVALID " --log-ip-options --log-tcp-options --log-tcp-sequence --log-level 4
	$IPT -A INPUT -m state --state INVALID -j DROP

	# Block sync
	$IPT -A INPUT -i ${IF_ETH} -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
	$IPT -A INPUT -i ${IF_ETH} -p tcp ! --syn -m state --state NEW -j DROP
	 
	# Block Fragments
	$IPT -A INPUT -i ${IF_ETH} -f  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
	$IPT -A INPUT -i ${IF_ETH} -f -j DROP
	 
	# Block bad stuff
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags ALL ALL -j DROP
	 
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets"
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
	 
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
	 
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets"
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS
	 
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan"
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans
	 
	$IPT  -A INPUT -i ${IF_ETH} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

	$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

	# OUTPUT:Utilização de serviços
	#######################

	$IPT -A OUTPUT -p tcp --sport 1024:65535 --dport	80 -m state --state NEW -j ACCEPT
	$IPT -A OUTPUT -p tcp --sport 1024:65535 --dport	443 -m state --state NEW -j ACCEPT

	$IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	22 -m state --state NEW -j ACCEPT
	$IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	22003 -m state --state NEW -j ACCEPT
	# $IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	443 -m state --state NEW -j ACCEPT
	# $IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	631 -m state --state NEW -j ACCEPT
	# $IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	646 -m state --state NEW -j ACCEPT
	# $IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	80 -m state --state NEW -j ACCEPT
	# $IPT -A OUTPUT -p tcp --sport 1024:65535 --dport 	8080 -m state --state NEW -j ACCEPT
	
	$IPT -A OUTPUT -p udp --sport 1024:65535 --dport 	53 -m state --state NEW -j ACCEPT

	# INPUT: Serviços disponiveis
	##################
	
	## rede externa
	$IPT -A INPUT -p tcp --sport 1024:65535 --dport 	80 -m state --state NEW -j ACCEPT
	$IPT -A INPUT -p tcp --sport 1024:65535 --dport 	443 -m state --state NEW -j ACCEPT
	

	# $IPT -A INPUT -p tcp -i $IF_LAN1 --sport 1024:65535 --dport 	111 -m state --state NEW -j ACCEPT
	# $IPT -A INPUT -p tcp -i $IF_LAN1 --sport 1024:65535 --dport 	22003 -m state --state NEW -j ACCEPT
	# $IPT -A INPUT -p tcp -i $IF_LAN1 --sport 1024:65535 --dport 	3306 -m state --state NEW -j ACCEPT
	# $IPT -A INPUT -p tcp -i $IF_LAN1 --sport 1024:65535 --dport 	631 -m state --state NEW -j ACCEPT
	# $IPT -A INPUT -p tcp -i $IF_LAN1 --sport 1024:65535 --dport 	646 -m state --state NEW -j ACCEPT
	# $IPT -A INPUT -p tcp -i $IF_LAN1 --sport 1024:65535 --dport 	8080 -m state --state NEW -j ACCEPT
	
	# $IPT -A INPUT -p udp -i $IF_LAN1 --sport 1024:65535 --dport 	631 -m state --state NEW -j ACCEPT
	# $IPT -A INPUT -p udp -i $IF_LAN1 --sport 1024:65535 --dport 	646 -m state --state NEW -j ACCEPT
	
	$IPT -A INPUT -i $IF_ETH -p icmp --icmp-type echo-request -j DROP
	$IPT -A OUTPUT -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT # como cliente:
	$IPT -A INPUT -p icmp --icmp-type echo-request -m state --state NEW -m limit --limit 1/s -j ACCEPT # como servidor:
	# $IPT -A FORWARD -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT;

	echo "Portas de serviços liberadas ..... [ok]"
}


	#######################
	# Segurança
	#######################
function security() {

	## pacotes icmp especiais
	$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
	$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
	$IPT -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT
	$IPT -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
	$IPT -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT
	$IPT -A OUTPUT -p icmp --icmp-type parameter-problem -j ACCEPT

	# ### Descarte de pacotes nao identificados ICMP
	$IPT -A OUTPUT -m state -p icmp --state INVALID -j DROP
	$IPT -A INPUT -m state -p icmp --state INVALID -j DROP
	$IPT -A FORWARD -m state -p icmp --state INVALID -j DROP

	### Segurança Diversa (o firewall responda na mesma interface que foram originados os pacotes)
	echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

	### Impedindo ataque Ping of Death na rede
	$IPT -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

	### Impedindo ataque de Denial Of Service Dos na rede e servidor
	$IPT -I FORWARD -p tcp -m limit --limit 1/s -j ACCEPT
	$IPT -A INPUT -p tcp -m limit --limit 1/s -j ACCEPT

	### Impedindo ataque Port Scanners na rede e no Firewall
	$IPT -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
	$IPT -I INPUT -p udp --dport 33435:33525 -j LOG --log-level info --log-prefix 'SCANNERS DROPADO>'
	$IPT -A INPUT -p udp --dport 33435:33525 -j DROP
	$IPT -I FORWARD -p udp --dport 33435:33525 -j LOG --log-level info --log-prefix 'SCANNERS DROPADO NA REDE>'
	$IPT -A FORWARD -p udp --dport 33435:33525 -j DROP

	### Bloqueando tracertroute
	$IPT -A INPUT -p udp -s 0/0 -i $IF_ETH --dport 33435:33525 -j REJECT
	$IPT -A INPUT -p udp -s 0/0 -i $IF_LAN1 --dport 33435:33525 -j REJECT


	### Bloquear Back Orifice na rede
	$IPT -I INPUT -p tcp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE DROPADO>'
	$IPT -A INPUT -p tcp --dport 31337 -j DROP
	$IPT -I INPUT -p udp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE UDP>'
	$IPT -A INPUT -p udp --dport 31337 -j DROP
	$IPT -I FORWARD -p tcp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE NA REDE>'
	$IPT -A FORWARD -p tcp --dport 31337 -j DROP
	$IPT -I FORWARD -p udp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE NA REDE UDP>'
	$IPT -A FORWARD -p udp --dport 31337 -j DROP

	### Bloquear NetBus na rede
	$IPT -I INPUT -p tcp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS >'
	$IPT -A INPUT -p tcp --dport 12345 -j DROP
	$IPT -I INPUT -p udp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS UDP>'
	$IPT -A INPUT -p udp --dport 12345 -j DROP
	$IPT -I FORWARD -p tcp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS NA REDE>'
	$IPT -A FORWARD -p tcp --dport 12345 -j DROP
	$IPT -I FORWARD -p udp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS UDP>'
	$IPT -A FORWARD -p udp --dport 12345 -j DROP

	### desativar o suporte a ping broadcasts
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

	### Se não atuar como um roteador, é prudente desativar redirecionamento de ICMP
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects


	### Ativando protecao contra responses bogus
	echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

	### Protecao contra worms
	$IPT -I FORWARD -p tcp --dport 135 -j LOG --log-level info --log-prefix 'WORMS REDE>'
	$IPT -A FORWARD -p tcp --dport 135 -j DROP
	$IPT -I INPUT -p tcp --dport 135 -j LOG --log-level info --log-prefix 'WORMS >'
	$IPT -A INPUT -p tcp --dport 135 -j DROP

	### Desativada o suporte ao source routing (permite falsear pacotes)
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

	# "Proteção contra Syn-floods(tempo de resposta para pacotes)"
	$IPT -N syn_flood
	$IPT -A syn_flood -m limit --limit 10/second --limit-burst 5 -j RETURN
	$IPT -A syn_flood -j DROP
	$IPT -A INPUT -p tcp --syn -j syn_flood
	$IPT -A FORWARD -p tcp --syn -m limit --limit 2/s -j ACCEPT
	### SYN cookies. (consiste em enviar um grande volume de pacotes SYN)
	echo "1" > /proc/sys/net/ipv4/tcp_syncookies


	###################
	# "Port scanners ocultos"
	$IPT -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
	    
	    	    
	###################
	# "Proteção Contra IP Spoofing para Rede Local"
	$IPT -A INPUT -s $REDE -i !$IF_LAN1 -j DROP
	$IPT -A INPUT ! -s $REDE -i $IF_LAN1 -j DROP

	echo "Segurança da rede, Firewall e gerando logs de portas"
}



#######################
## Liberar rede interna  
#######################
function rules_forward(){


	#################################################
	# COMPARTILHANDO LINK EHT0 POSTROUTING MASQUERADE
	#################################################

	# IF_ETH -j MASQUERADE;

	for rede in ${!LAN_TCP[*]}; do
		for porta in ${LAN_TCP[$rede]}; do
		$IPT -A FORWARD -s $rede -p tcp --dport $porta -m state --state NEW -j ACCEPT;	
		done
	done

	for rede in ${!LAN_UDP[*]}; do
		for porta in ${LAN_UDP[$rede]}; do
		$IPT -A FORWARD -s $rede -p udp --dport $porta -m state --state NEW -j ACCEPT;	
		done
	done

	###########################
	# PREROUTING
	###########################	
	
	# $IPT -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128
	
	# Liberar acesso remoto rede interna
	# $IPT -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 3128
	# $IPT -A INPUT -p tcp --dport 3389 -j ACCEPT
	# $IPT -A FORWARD -p tcp --dport 3389 -d 10.1.1.10 -j ACCEPT
	# $IPT -t nat -A PREROUTING -i eth0 -p tcp --dport 3389 -j DNAT --to 10.1.1.10


	
}


########################################­###
# System service
########################################­###

case $1 in
	"on" )
		kernel 1;
		rules_clear
		modules
		rules
		security
		# rules_forward
		rules_default DROP
		
		iptables -L

		echo "Ativado.........[ok]";
		;;
	"off" )
		kernel 0;
		rules_clear
		rules_default ACCEPT
		echo "Desativado......[ok]";
		;;
	* )
	echo "ERRO!!! Tente o comando: $0 {on|off}";
	;;
esac