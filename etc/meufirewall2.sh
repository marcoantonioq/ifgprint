#!/bin/sh
iptables -F
iptables -t filter -F
iptables -t filter -Z
iptables -t mangle -F
iptables -t mangle -Z 
iptables -t nat -F
iptables -t nat -Z
iptables -X 

case $1 in
	"off" )
		echo "Clear rules.....[ok]";
		exit;
		;;
esac


# INPUT iptables Rules
# Accept loopback input
iptables -A INPUT -i lo -p all -j ACCEPT

# Allow
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

### Spoofing pacotes ROP
iptables -A INPUT -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP


# para proteção contra ataques
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
# iptables -A INPUT -p icmp -m icmp -m limit --limit 1/s -j ACCEPT
# -m limit --limit 1/s --limit-burst 3 -j RETURN

# Droping todos os pacotes inválidos
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Inundação de pacotes RST, Rejeição ataque smurf
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Proteger scanneamento de portas
# Atacante IP será bloqueado por 24 horas (3600 x 24 = 86400 segundos)
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Remover atacando IP após 24 horas
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# Estas regras adicionar à lista de scanners portscan, e registrar a tentativa.
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP


################# Abaixo estão as regras do iptables para ENTRADA ############################

iptables -A INPUT -p tcp -i eth0 -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -i eth0 -m tcp --dport 25 -j ACCEPT
iptables -A INPUT -p tcp -i eth0 -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -i eth0 -m tcp --dport 631 -j ACCEPT
iptables -A INPUT -p tcp -i eth0 -m tcp --dport 80 -j ACCEPT

# iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT


################# Abaixo estão as regras do iptables para SAÍDA ############################

## Allow loopback OUTPUT 
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SMTP = 25
# DNS =53
# HTTP = 80
# HTTPS = 443
# SSH = 22
# SSH = 22003

iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 22003 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 25 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 631 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT

# Allow pings
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT


## Default: Reject
iptables -A OUTPUT -j REJECT
iptables -A FORWARD -j REJECT
iptables -A INPUT -j REJECT