#!/bin/sh
#
#############################################################################
#
#  File: firewall1.sh
#  Version 1.0
#  This is the main script for Bunplugged (psad, fwsnort and fwknop) nflog logs
#  everything it has also NAT and spoofing rules which are olny relevant if you have 
#  2 network interfaces in that  case you should set INT_INTF  INT_NETS INT_NETD
#  accordingly as well as setting DNS internaly. This is based on ipset  the
#  localnetip is all ipv4 adresses. Change it to -s 10.0.0.0/8 192.168.0.0/16
#  -m iprange --src-range 172.16.0.0-172.31.0.0 For the securezone led to work you need
#  to setup like this sudo echo netfilter-Isecure >/sys/class/input3::capslock/trigger
#  This is a seven user scipt being that only the users are allowed access so you will
#  need to set the user groups also. Since IPV6 is not wildly used it is only used for
#  secure websites. Logging is split for admin related it is logged to syslog and for
#  user related logged to nflog which you can seprate into diffrent groups.
#  Please note that the blacklists used by ipset use only one addresses and need to be
#  updated when going online unless they are downloaded from our website. The rules are
#  made to be complete and loaded as needed to enable integrty checking so all the rules   
#  are here some need to be chosen with the insert option.
#  PLEASE NOTE the blocks of bad words and all ipset sets is a network level 3 packet
#  filtering not application filtering please use squid for filtering.
#  Basic Firewall Script based on Linux Firewalls from  Michael Rash (mbr@cipherdyne.org)
#  Blacklist from n0where.com and Oskar Andreasson from Iptables Tutorial fame Secure mode
#  is based on a github project.
#  Thank You all as was said before (in the man pages of ipset) I stand on he shoulders of
#  gaints as all of open source.   
#  License (GNU Public License):
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#   USA
#
#
#############################################################################
#

IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPSET=/sbin/ipset 
MODPROBE=/sbin/modprobe
IPSETSAVEPATH=/etc/ipsetlists/
INT_NETS="-m set --match-set LocalNetip src" 
INT_NETD="-m set --match-set LocalNetip dst" 
INT_INTF=" " #edit to check
GROUP1=1000
GROUP2=1100
GROUP3=1200
GROUP4=1300
GROUP5=1400
GROUP6=1500
GROUP7=1600

# Open DNS servers: see cat /etc/resolvconf/resolv.conf.d need to add to list in computer
DNS_SERVER="208.67.222.222 208.67.220.220" 
DNS_SERVER6="2620:0:ccc::2 2620:0:ccd::2" 

# Allow connections to these package servers in ipset
PACKAGE_SERVER="-m set --match-set UServers dst"
PACKAGE_SERVER6="fe80::/10 " 

# Bad Words Blacklist Try to keep to a minimum for it makes a lot of rules
BAD_WORDS="dick chix xxx erotic porn slut fetish smut lesbian boob cum gay sodom adultsite adultsonly adultweb blowjob cumshot cyberlust masturbate pornstar sexdream striptease"

### Set up lists in Ipset 

$IPSET restore < $IPSETSAVEPATHLocalNetip.restore 
$IPSET restore < $IPSETSAVEPATHUServers.restore
$IPSET restore < $IPSETSAVEPATHBlacklist.restore 
$IPSET restore < $IPSETSAVEPATHWhitelist.restore 
$IPSET restore < $IPSETSAVEPATHEFshare.restore 
$IPSET restore < $IPSETSAVEPATHSecure.restore 
$IPSET restore < $IPSETSAVEPATHSecure6.restore 
$IPSET restore < $IPSETSAVEPATHpg2.restore

### flush existing rules and set chain policy setting to DROP

### Load Modules
$MODPROBE ip_conntrack
$MODPROBE iptable_nat
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_nat_ftp

echo "[+] Flushing existing iptables rules..."
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -X
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -F -t Mangle  
$IPTABLES -t Mangle -X 

### IPV6 Rules
echo -n "[+] Setting up IPV6 traffic"
$IP6TABLES -P INPUT DROP
$IP6TABLES -P OUTPUT DROP
$IP6TABLES -P FORWARD DROP

## State Tracking
$IP6TABLES -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IP6TABLES -A INPUT -m state --state INVALID -j DROP
$IP6TABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
echo -n .

## ICMP Rules
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
echo -n .
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 900/min -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type echo-reply -m limit --limit 900/min -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -m hl --hl-eq 255 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -m hl --hl-eq 255 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type redirect -m hl --hl-eq 255 -j ACCEPT
$IP6TABLES -A INPUT -m state --state NEW -m udp -p udp -s fe80::/10 --dport 546 -6 -j ACCEPT 
echo -n .
$IP6TABLES -A INPUT -p icmpv6 -j LOG --log-prefix "DROP ICMPv6 " --log-ip-options --log-tcp-options
echo -n .
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
echo -n .
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT
$IP6TABLES -A OUTPUT -p icmpv6 --icmpv6-type router-solicitation -m hl --hl-eq 255 -j ACCEPT
echo -n .

## Service Rules
$IP6TABLES -N Service
$IP6TABLES -A Service -p tcp -m multiport --port 21,80,443  -d $PACKAGE_SERVER6 -m state --state NEW,RELATED -j ACCEPT
$IP6TABLES -A Service -p tcp --dport 873 -d $PACKAGE_SERVER6 -m state --state NEW -j ACCEPT
$IP6TABLES -A Service -p udp --dport 873 -d $PACKAGE_SERVER6 -m state --state NEW -j ACCEPT 
echo -n .
$IPTABLES -N Service
$IPTABLES -A Service -p tcp -m multiport --port 21,80,443 -d $PACKAGE_SERVER -m state --state NEW,RELATED -j ACCEPT
echo -n .

##Secure Rules
$IP6TABLES -N Secureout 
$IP6TABLES -A Secureout -p udp ! --dport 53 -j REJECT 
$IP6TABLES -A Secureout -p tcp ! --dport 53 -m set ! --match-set Secure6 dst -j REJECT --reject-with tcp-reset
$IP6TABLES -A Secureout -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Secure Zone Enabled v6"
$IP6TABLES -A Secureout -p tcp --match multiport --dports 80,443,8080 -j LED --led-trigger-id Isecure --led-delay 50 --led-always-blink 
$IP6TABLES -A Secureout -p tcp --match multiport --dports 80,443,8080 -m state --state NEW,ESTABLISHED -j ACCEPT

##User Rules
# Level 1 No access
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP1 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP1 v6" 
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP1 -j REJECT
# Level 2 No access
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP2 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP2 v6" 
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP2 -j REJECT
echo -n .
# Level 3 Only Services
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP3 -j Service
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP3 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP3 v6" 
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP3 -j REJECT
# Level 4 Only Services
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP4 -j Service
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP4 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP4 v6" 
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP4 -j REJECT
# Level 5 Services Securezone
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP5 -g Secureout
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP5 -g Service
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP5 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP5 v6"
# Level 6 Services Securezone
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP6 -g Secureout
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP6 -g Service
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP6 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP6 v6" 
# Level 7 Services Securezone
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP7 -g Secureout
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP7 -g Service
$IP6TABLES -A OUTPUT -m owner --gid-owner $GROUP7 -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Attempted Access $GROUP7 v6" 
echo -n .

## Dns Rules
echo -n "Allowing DNS lookups"
$IP6TABLES -A INPUT -p udp -s $DNS_SERVER6 --sport 53 -m state --state NEW -j ACCEPT
$IP6TABLES -A INPUT -p tcp -s $DNS_SERVER6 --sport 53 -m state --state NEW -j ACCEPT
$IP6TABLES -A OUTPUT -p udp -d  $DNS_SERVER6 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IP6TABLES -A OUTPUT -p tcp -d $DNS_SERVER6 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
echo ...

# Addtional Rules
#IP6TABLES -I Secureout


### User Tables ###
echo -n "[+] Enabling..."

## Secure Settings for banking sites if not added in with -I will drop
echo -n "Secure Zone"
$IPTABLES -N Secureout 
$IPTABLES -A Secureout -p udp ! --dport 53 -j REJECT 
$IPTABLES -A Secureout -p tcp ! --dport 53 -m set ! --match-set Secure dst -j REJECT --reject-with tcp-reset
$IPTABLES -A Secureout -j NFLOG --nflog-range 80 --nflog-group 2 --nflog-prefix "Secure Zone Enabled" 
$IPTABLES -A Secureout -p tcp --match multiport --dports 80,443 -j LED --led-trigger-id Isecure --led-delay 50 --led-always-blink 
$IPTABLES -A Secureout -p tcp --match multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
echo -n .

## Samba Rules 
echo -n "Microsoft Networking"
$IPTABLES -N Sambat
$IPTABLES -A Sambat -p tcp -m multiport --port 137,138,139,445 $INT_NETD -m state --state NEW -j ACCEPT
$IPTABLES -A Sambat -p tcp -m multiport --port 137,138,139,445 $INT_NETS -m state --state NEW -j ACCEPT
$IPTABLES -N Sambau
$IPTABLES -A Sambau -p udp -m multiport --port 137,138,139,445 $INT_NETD -m state --state NEW -j ACCEPT
$IPTABLES -A Sambau -p udp -m multiport --port 137,138,139,445 $INT_NETS -m state --state NEW -j ACCEPT
echo -n ...

## Apple Talk Rules 	
echo -n  "Apple Networking"
$IPTABLES -N AppleTalkt
$IPTABLES -A AppleTalkt -p tcp -m multiport --port 201,202,204,206 $INT_NETD -m state --state NEW -j ACCEPT
$IPTABLES -A AppleTalkt -p tcp -m multiport --port 201,202,204,206 $INT_NETS -m state --state NEW -j ACCEPT
$IPTABLES -N AppleTalku
$IPTABLES -A AppleTalku -p udp -m multiport --port 201,202,204,206 $INT_NETD -m state --state NEW -j ACCEPT
$IPTABLES -A AppleTalku -p udp -m multiport --port 201,202,204,206 $INT_NETS -m state --state NEW -j ACCEPT
echo -n ...

## Service Rules
echo -n  "Services"
$IPTABLES -N Servicest
$IPTABLES -A  Servicest -p tcp -m multiport --port 43,123 -m state --state NEW -j ACCEPT 
# Package server 
$IPTABLES -A Servicest -p tcp -m multiport --port 21,80,443 $PACKAGE_SERVER -m state --state NEW,RELATED -j ACCEPT
$IPTABLES -A Servicest -p tcp --dport 873 $PACKAGE_SERVER -m state --state NEW -j ACCEPT
# For redshift
$IPTABLES -A Servicest -p tcp --dport 80 -s 185.29.135.190 -m state --state NEW -j ACCEPT
$IPTABLES -N Servicesu
$IPTABLES -A Servicesu -p udp --dport 123 -m state --state NEW -j ACCEPT 
$IPTABLES -A Servicesu -p udp --dport 873 $PACKAGE_SERVER -m state --state NEW -j ACCEPT 
echo -n ...

## Email Rules
echo -n "Email"
$IPTABLES -N Emailt
$IPTABLES -A Emailt -p tcp -m multiport --port 110,143,993,995 -m state --state NEW -j ACCEPT # not needed
$IPTABLES -A Emailt -p tcp --dport 25 -m state --state NEW -j ACCEPT 
echo ...

##Email File Share
echo -n "Email File Sharing"
$IPTABLES -N EFsharet 
$IPTABLES -A EFsharet -p tcp -m multiport --port 20,21,873,989,990  -m set --match-set EFshare dst -m state --state NEW,RELATED -j NFLOG --nflog-group 2 --nflog-prefix "Email File Share"
$IPTABLES -A EFsharet -p tcp -m multiport --port 20,21,873,989,990  -m set --match-set EFshare dst -m state --state NEW,RELATED -j ACCEPT
$IPTABLES -N EFshareu
$IPTABLES -A EFshareu -p udp --dport 873  -m set --match-set EFshare dst -m state --state NEW,RELATED -j NFLOG --nflog-group 2 --nflog-prefix "Email File Share"
$IPTABLES -A EFshareu -p udp --dport 873  -m set --match-set EFshare dst -m state --state NEW,RELATED -j ACCEPT
echo -n ...

## Ftp Rules 
echo -n  "File Sharing"
$IPTABLES -N FTPt
$IPTABLES -A FTPt -p tcp -m multiport --port 20,21,873,989,990 -m state --state NEW,RELATED -j NFLOG --nflog-group 2 --nflog-prefix "File Share"
$IPTABLES -A FTPt -p tcp -m multiport --port 20,21,873,989,990 -m state --state NEW,RELATED -j ACCEPT
$IPTABLES -N FTPu
$IPTABLES -A FTPu -p udp --dport 873 -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "File Share"
$IPTABLES -A FTPu -p udp --dport 873 -m state --state NEW -j ACCEPT
echo -n ...

## Http Https SSH Open VPN Rules
echo -n  "HTTP HTTPS IPSEC Open VPN"
$IPTABLES -N HTTPt
$IPTABLES -A HTTPt -p tcp -m multiport --port 22,80,443,500,1194,8080 -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "HTTP"
$IPTABLES -A HTTPt -p tcp -m multiport --port 22,80,443,500,1194,8080 -m state --state NEW -j ACCEPT
$IPTABLES -N HTTPu
$IPTABLES -A HTTPu -p udp -m multiport --port 500,1194 -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "HTTP"
$IPTABLES -A HTTPu -p udp -m multiport --port 500,1194 -m state --state NEW -j ACCEPT
echo ...

###### INPUT chain ###### 
#
echo -n "[+] Setting up INPUT chain..."

### State tracking rules

$IPTABLES -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m state --state INVALID -j DROP

#Additional Rules
$IPTABLES -A Secureblock
# IPTABLES -I INPUT -j Securein 

## DNS rules 
# not always will send on these ports but this is for the initial connection
echo -n "Allowing DNS lookups"
for ip in $DNS_SERVER
do
	$IPTABLES -A INPUT  -p udp -s $ip --sport 53 -m state --state NEW -j ACCEPT
	$IPTABLES -A INPUT  -p tcp -s $ip --sport 53 -m state --state NEW -j ACCEPT
done
echo -n ...

## Blacklists
echo -n "Blocking Bad Websites"
# PG2 Blacklists
$IPTABLES -A INPUT -m set --match-set pg2 src -j LOG --log-prefix "DROP PG2 List " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m set --match-set pg2 src -j REJECT
echo -n .
# Blacklists
$IPTABLES -A INPUT -m set --match-set Blacklist src -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "BLACKLIST"
$IPTABLES -A INPUT -m set --match-set Blacklist src -j REJECT
echo -n ..

## Block Bad Words
echo -n "Blocking Bad Words"
for word in $BAD_WORDS
do
	$IPTABLES -A INPUT -m string --string "$word" --algo bm --icase -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "BLACK WORDS" 
	$IPTABLES -A INPUT -m string --string "$word" --algo bm --icase -j REJECT
done
echo ...

# Accept networking
$IPTABLES -A INPUT -p tcp -m state --state NEW -g Sambat
$IPTABLES -A INPUT -p udp -m state --state NEW -g Sambau
$IPTABLES -A INPUT -p tcp -m state --state NEW -g AppleTalkt
$IPTABLES -A INPUT -p udp -m state --state NEW -g AppleTalku

# Accept all others
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

### anti-spoofing rules this is rule needs 2 interfaces to work 
#$IPTABLES -A INPUT -i $INT_INTF -m set ! --match-set LocalNetip src -j LOG --log-prefix "SPOOFED PKT " --log-ip-options --log-tcp-options
#$IPTABLES -A INPUT -i $INT_INTF -m set ! --match-set LocalNetip src -j DROP

### ACCEPT rules
$IPTABLES -A INPUT -p icmp -m limit --limit 900/min -j ACCEPT 
$IPTABLES -A INPUT -p icmp -j LOG --log-prefix "DROP ICMP " --log-ip-options --log-tcp-options

### default INPUT LOG rule
$IPTABLES -A INPUT ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

## Make sure that loopback traffic is accepted
$IPTABLES -A INPUT -s 127.0.0.1  -j ACCEPT 

###### OUTPUT chain ######

echo -n "[+] Setting up OUTPUT chain..."

### State tracking rules
$IPTABLES -A OUTPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP

#Additional Rules
# IPTABLES -I OUTPUT  -g Secureout  
# IPTABLES -I OUTPUT  -g Nologs 

$IPTABLES -A OUTPUT -p tcp --match multiport --dports 80,443,8080 -m set --match-set Secure src -j Secureblock

### ACCEPT rules for allowing connections out
## DNS rules 
echo -n  "Allowing DNS lookups"
for ip in $DNS_SERVER
do
	$IPTABLES -A OUTPUT -p udp -d $ip --dport 53 -m state --state NEW -j ACCEPT
	$IPTABLES -A OUTPUT -p tcp -d $ip --dport 53 -m state --state NEW -j ACCEPT
	$IPTABLES -t nat -A OUTPUT -o !lo -p tcp -m tcp --dport 53 -j DNAT --to-destination $ip:53  
	$IPTABLES -t nat -A OUTPUT -o !lo -p udp -m udp --dport 53 -j DNAT --to-destination $ip:53 

done
### ACCEPT rules
$IPTABLES -A INPUT -p icmp -m limit --limit 900/min -j ACCEPT 
$IPTABLES -A INPUT -p icmp -j LOG --log-prefix "DROP ICMP " --log-ip-options --log-tcp-options

### default INPUT LOG rule
$IPTABLES -A INPUT ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

## Make sure that loopback traffic is accepted
$IPTABLES -A INPUT -s 127.0.0.1  -j ACCEPT 
echo -n ...

## Blacklists
echo -n "Blocking Bad Websites"
# PG2 Blacklists
$IPTABLES -A OUTPUT -m set --match-set pg2 dst -j LOG --log-prefix "DROP PG2 List " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m set --match-set pg2 dst -j REJECT
echo -n ..
# Blacklists
$IPTABLES -A OUTPUT -m set --match-set Blacklist dst -j NFLOG --nflog-group 2 --nflog-prefix "BLACKLIST"
$IPTABLES -A OUTPUT -m set --match-set Blacklist dst -j REJECT
echo -n .

## Block Bad Words 
echo -n "Blocking Bad Words"
for word in $BAD_WORDS
do
	$IPTABLES -A OUTPUT -m string --string "$word" --algo bm --icase  -j NFLOG --nflog-group 2 --nflog-prefix "BLACK WORDS" 
	$IPTABLES -A OUTPUT -m string --string "$word" --algo bm --icase -j DROP
done
echo ...

### Levels 
echo -n [+] Enabling Users

## Level 1 Block all
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP1 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP1"
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP1 -j REJECT --reject-with icmp-admin-prohibited 
echo -n .

## Level 2 Only internal
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2  -m set ! --match-set LocalNetip dst -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP2"
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -m set ! --match-set LocalNetip dst -j DROP
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p tcp -g Sambat
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p tcp -g AppleTalkt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p tcp -g FTPt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p tcp -g HTTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p udp -g Sambau
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p udp -g AppleTalku
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p udp -g FTPu
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -p udp -g HTTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP2 -m owner --gid-owner $GROUP2 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP2"
echo -n .

## Level 3 Only Allow Apps redshift, NTP, rsync and updates
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p tcp -g Sambat 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p tcp -g AppleTalkt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p tcp -g Servicest 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p tcp $INT_NETD -m state --state NEW -g FTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p tcp $INT_NETD -m state --state NEW -g HTTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p udp -g Sambau 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p udp -g AppleTalku 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p udp -g Servicesu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p udp $INT_NETD -m state --state NEW -g FTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -p udp $INT_NETD -m state --state NEW -g HTTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP3 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP3"
echo -n .

## Level 4 Add Email and File Sharing 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp -g Sambat 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp -g AppleTalkt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp -g Emailt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp -g EFsharet
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp -g Servicest 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp $INT_NETD -g FTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p tcp $INT_NETD -g HTTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p udp -g Sambau 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p udp -g AppleTalku 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p udp -g EFshareu
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p udp -g Servicesu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p udp $INT_NETD -g FTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -p udp $INT_NETD -g HTTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP4 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP4"
echo -n .

## Level 5 Add Whitelist and Secure websites (utilities) 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g Secureout
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g Emailt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g EFsharet
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g FTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g Sambat 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g AppleTalkt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -g Servicest
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp -m set --match-set Whitelist dst -g  HTTPt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p tcp $INT_NETD  -g HTTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p udp -g EFshareu
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p udp -g FTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p udp -g Sambau 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p udp -g AppleTalku 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p udp -g Servicesu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -p udp $INT_NETD -j HTTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP5 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP5 "
echo -n .

## Level 6  Throttled connection 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g Secureout
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g Emailt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g EFsharet
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g FTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -m set --match-set Whitelist dst -g  HTTPt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -m multiport --port 80,443 -m connbytes --connbytes 50000:50000 --connbytes-dir reply --connbytes-mode bytes -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Exceeded Limits $GROUP6"
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -m multiport --port 80,443 -m connbytes --connbytes 50000:50000 --connbytes-dir reply --connbytes-mode bytes -j DROP
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g HTTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g Sambat 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g AppleTalkt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g Servicest
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p tcp -g Secureout
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p udp -g EFshareu
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p udp -g FTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p udp -g HTTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p udp -g Sambau 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p udp -g AppleTalku 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -p udp -g Servicesu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP6 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP6"
echo -n .

## Level 7 Allow everything Secure enabled above
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g Secureout
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g Emailt
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g EFsharet
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g FTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g HTTPt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g Sambat 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g AppleTalkt 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p tcp -g Servicest
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p udp -g EFshareu
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p udp -g FTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p udp -g HTTPu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p udp -g Sambau 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p udp -g AppleTalku 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -p udp -g Servicesu 
$IPTABLES -A OUTPUT -m owner --gid-owner $GROUP7 -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Attempted Access $GROUP7"
echo .

## Allow Kernel and icmp
$IPTABLES -A OUTPUT -m owner --socket-exists -j NFLOG --nflog-group 2 --nflog-prefix "NO user kernel " 
$IPTABLES -A OUTPUT -m owner --socket-exists -m connbytes --connbytes 25000:25000 --connbytes-dir reply --connbytes-mode bytes -j NFLOG --nflog-group 2 --nflog-range 100 --nflog-prefix "Kernel use to High"
$IPTABLES -A OUTPUT -m owner --socket-exists -m connbytes --connbytes 25000:25000 --connbytes-dir reply --connbytes-mode bytes -j DROP
$IPTABLES -A OUTPUT -m owner --socket-exists -j ACCEPT  
$IPTABLES -A OUTPUT -p icmp -j ACCEPT

### default OUTPUT LOG rule 
$IPTABLES -A OUTPUT ! -o lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### make sure that loopback traffic is accepted
$IPTABLES -A OUTPUT -s 127.0.0.1 -j ACCEPT 	

###### FORWARD chain ######    

echo -n "[+] Setting up FORWARD chain..."

### state tracking rules

$IPTABLES -A FORWARD -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A FORWARD -m state --state INVALID -j DROP
$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

## Dns Rules
echo -n "Allowing DNS lookups"
for ip in $DNS_SERVER
do
	$IPTABLES -A FORWARD -p udp -s $ip --sport 53 -m state --state NEW -j ACCEPT
	$IPTABLES -A FORWARD -p tcp -s $ip --sport 53 -m state --state NEW -j ACCEPT
done
echo -n ...

## Block Bad Words 
echo -n "Blocking Bad Words"
for word in $BAD_WORDS
do
	$IPTABLES -A FORWARD -m string --string "$word" --algo bm --icase -j NFLOG --nflog-group 2 --nflog-prefix "BLACK WORDS" 
	$IPTABLES -A FORWARD -m string --string "$word" --algo bm --icase -j DROP
done
echo ...

### anti-spoofing rules 
# $IPTABLES -A FORWARD -i $INT_INTF !  $INT_NET -j LOG --log-prefix "SPOOOFED PKT " --log-ip-options --log-tcp-options  
# $IPTABLES -A FORWARD -i $INT_INTF !  $INT_NET -j DROP

### ACCEPT rules 

# can add in -i $INT_INTF before $INT_NETS for more security
$IPTABLES -A FORWARD -p tcp $INT_NETS -m state --state NEW,RELATED -j Servicest
$IPTABLES -A FORWARD -p udp $INT_NETS -m state --state NEW,RELATED -j Servicesu
$IPTABLES -A FORWARD -p tcp $INT_NETS --dport 43 -m state --state NEW,RELATED -j ACCEPT
$IPTABLES -A FORWARD -p icmp -j ACCEPT

## default LOG rule

$IPTABLES -A FORWARD ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### Forwarding ######

echo -n "[+] Enabling IP forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward
echo -n .
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
echo ..
exit

### EOF ###
