#!/bin/bash 

# First arg is a .pcap, .pcapng, .cap file 
FILE=$1

# Begins to parse command line args from arg 2
ARGS=${@:2} 

# Checks to see if Tshark is installed
Tshark="$(dpkg --list tshark\* 2>/dev/null | awk '/ii/{print $2}')"

# Color Constants
RED=$(tput sgr bold 0 1 ; tput setaf 1)
RESET=$(tput sgr0)

# Add space before 'read -p' 
cr=`echo $'\n'.`
cr=${cr%.}

# Checks user permission

if (( $EUID != 0 ))
then echo -e "\nUser must run ${0##*/} as UID 0 (root) to continue.\n" ; exit
fi


# If tshark not installed then this will prompt user to install it. 
if [ "$Tshark" != "tshark" ] ; then echo ; read -p "You need to install tshark before proceeding. Would you like to install tshark now? [y/N] " INSTALL ; if [[ "$INSTALL" = ["y","Y"] ]] ; then sudo apt-get install tshark ; exit 0 ; else echo -e "\n${RED} You will not be able to continue! ${RESET}\n"; exit 1 ; fi ; fi

# Help menu
function help() {
	
	echo -e "\n	Usage: ${RESET}\tFirst argument is your capture file followed by any number of arguments: ex => ${0##*/} <pcap>  <arg1> <arg2> <arg3>\n"
	echo "	-h	Help Menu"
	echo "	-a	Return all ARP reply messages and look for signs of MIT ARP POISONING"
	echo "	-c	Show IPv4 and IPv6 Conversations"
	echo "	-f	Fragmented Packets"
	echo "	-i	ICMP HOST Unreachable, PORT Unreachable Messages, and ICMP Packets larger than 160 bytes (Possible Covert Channel in data segment)"
	echo "	-l	Packet Lenghts"
	echo "	-p	Display all SYN, SYN/ACK, ACK to Ports 80 & 443. An unusual amount of SYNs W/O a SYN/ACK may indicate a scan."
	echo "	-s	Look for string in file"
	echo "	-t	Dumps a table of network TOP Talkers"
	echo "	-x	Export Objects from given protocol list. [ dicom, http, imf, smb, tftp ]."
	echo "	-A	Look for spoofed ARP messages"
	echo "	-B	Display HTTP Basic Authentication"
	echo "	-F-	Follow statistics of TCP packets and UDP packets as well as HTTP traffic (port 80). Usage: -F-tcp, -F-udp, -F-http"
	echo "	-H	Show HTTP Requests and HTTP Server Tree Connections"
	echo "	-I	Check for IPv6 Traffic"
	echo "	-L	Packets with lengths > 1280: This typically indicates transfer of data"
	echo "	-P	Protocol Hierachy Statistics"
	echo "	-Q	DNS Query Information"
	echo "	-R	Shows HTTP GET and POST Requests"	
	echo "	-S-	Display statistics and Enpoints: tcp, udp, usb, bluetooth, ethernet, wlan. Usage: -S-tcp, -S-udp, -S-usb, -S-bt, -S-eth, -S-wlan"
	echo " 	-T	Check for IPv6 Tunneled thru IPv4 using Teredo, Miredo, 6to4 etc"
	echo "	-U-	Uncommon TCP and UDP PORTS. Usage: -U-tcp or -U-udp"	
	echo "	-W	Search for SMB information (session request && smb.file contains 'exe' && server && path && password)"
	echo -e		"	-X	Look for scanning activity (Large amount of SYN packets)\n"
}

# A function for spacing 
function delimiter() {
echo -e "\n==============================================================================================================================="
}

# Checks to see if number of command line args is equal to zero...if so, displays help menu.
if (( $# == 0 ))
then
help ; exit 0
fi

# While the first arg is not a pcap or pcapng file print error messae and help menu. 
while ! ( [[ $FILE == *.pcap ]] || [[ $FILE == *.pcapng ]] || [[ $FILE == *.cap ]] )
do
echo -e "\n${RED} User must supply a .pcap or .pcapng file as first argument. ${RESET}\n" ; delimiter ; help ; exit 1
done  

if (( $# == 1 ))
then
echo -e "\n${RED} You must supply one or more arguments. Use '-h' for arguments ${RESET}\n"
exit 1
fi

# Ensures that '-h' cannot be used in conjunction with other flags
for valid in $ARGS
do
	while [[ $valid == -h ]] || [[ $valid == [a\\-z] ]] || [[ $valid == - ]] || [[ $valid == [A-Z] ]]
	do 
	help | tail -26 ; exit 1
	done
done

# While the number of command line args is greater than zero perform these actions.
while (( $# > 0 ))
do
while getopts :S:acfhilpstxABHILF:PQU:RTWX arg ; do # These are all the flags for the program
for flag in $ARGS	# Validates flags used
	do
		if ! ( [ "$flag" = "-W" ] || [ "$flag" = "-t" ] || [ "$flag" = "-p" ] || [ "$flag" = "-s" ] || [ "$flag" = "-a" ] || [ "$flag" = "-f" ] || [ "$flag" = "-Q" ] || [ "$flag" = "-c" ] || [ "$flag" = "-P" ] || [ "$flag" = "-h" ] || [ "$flag" = "-i" ] || [ "$flag" = "-S-tcp" ] || [ "$flag" = "-S-udp" ] || [ "$flag" = "-S-bt" ] || [ "$flag" = "-S-usb" ] || [ "$flag" = "-S-eth" ] || [ "$flag" = "-S-wlan" ] || [ "$flag" = "-U-udp" ] || [ "$flag" = "U-tcp" ] || [ "$flag" = "-U-tcp" ] || [ "$flag" = "-F-tcp" ] || [ "$flag" = "-F-udp" ] || [ "$flag" = "-F-http" ] || [ "$flag" = "-l" ] || [ "$flag" = "-L" ] || [ "$flag" = "-H" ] || [ "$flag" = "-X" ] || [ "$flag" = "-x" ] || [ "$flag" = "-R" ] || [ "$flag" = "-B" ] || [ "$flag" = "-A" ] || [ "$flag" = "-I" ] || [ "$flag" = "-T" ] )
        then
        echo -e "\n$(tput sgr bold 0 1)$(tput setaf 1) Invalid Option: '$flag'\t\t$(tput setaf 2) Valid Options are: -a, -c, -f, -i, -l, -p, -s, -t, -x, -A, -B, -F-args, -H, -I, -L, -P, -Q, -R, -T, -S-args, -U-args, -W, -X $(tput sgr0)\n"
        exit 1
        fi
	done

case $arg in
	
	I)	echo -e "\n\t\t\t\tChecking for IPv6 Traffic" ; delimiter ; echo
		tshark -n -r $FILE icmpv6 2>/dev/null | awk '{print substr ($0, index($0,$3)) }' | sed 's/\(.*\)/       \1/' ; delimiter ; echo -e "\n\t\t\t\tChecking for Fragmented IPv6 Packets" ; delimiter ; for flag in ipv6.fraghdr ipv6.fraghdr.nxt ipv6.fraghdr.more ; do echo ; tshark -n -r $FILE $flag 2>/dev/null ; done | awk '{print substr ($0, index($0,$3)) }' | sed 's/\(.*\)/       \1/' | sort -u ; delimiter
		;;
		
	S)
		OPT=$OPTARG
		if [[ $OPT = -tcp ]]
		then
		echo -e "\n\t\t\t\tTCP CONVERSATIONS and STATISTICS\n" ; delimiter ; tshark -n -r $FILE -qz conv,tcp -qz ipv6_srcdst,tree -qz ip_srcdst,tree 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tTCP ENDPOINTS\n" ; delimiter ; tshark -n -r $FILE -qz endpoints,tcp 2>/dev/null ; delimiter ; fi
		if [[ $OPT = -udp ]]
		then
		echo -e "\n\t\t\t\tUDP CONVERSATIONS\n" ; delimiter ; tshark -n -r $FILE -qz conv,udp 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tUDP ENDPOINTS\n" ; delimiter ; tshark -n -r $FILE -qz endpoints,udp 2>/dev/null ; echo ; fi
		if [[ $OPT = -bt ]]
		then
		echo -e "\n\t\t\t\tBLUETOOTH CONVERSATIONS\n" ; delimiter ; tshark -n -r $FILE -qz conv,bluetooth 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tBLUETOOTH ENDPOINTS\n" ; delimiter ; tshark -n -r $FILE -qz endpoints,bluetooth 2>/dev/null ; echo ; fi
		if [[ $OPT = -usb ]]
		then
		echo -e "\n\t\t\t\tUSB CONVERSATIONS\n" ; delimiter ; tshark -n -r $FILE -qz conv,usb 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tUSB ENDPOINTS\n" ; delimiter ; tshark -n -r $FILE -qz endpoints,usb 2>/dev/null ; echo ; fi
		if [[ $OPT = -eth ]]
		then
		echo -e "\n\t\t\t\tETHERNET CONVERSATIONS\n" ; delimiter ; tshark -n -r $FILE -qz conv,eth 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tETHERNET ENDPOINTS\n" ; delimiter ; tshark -n -r $FILE -qz endpoints,eth 2>/dev/null ; echo ; fi
		if [[ $OPT = -wlan ]]
		then
		echo -e "\n\t\t\tWIRELESS (802.11 Addresses) CONVERSATIONS" ; delimiter ; tshark -n -r $FILE -qz conv,wlan 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tWIRELESS ENDPOINTS" ; delimiter ; tshark -n -r $FILE -qz endpoints,wlan 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tWIRELESS AUTHENTICATION FRAMES" ; delimiter ; tshark -n -r $FILE -Y "(wlan.fc.type_subtype eq 11)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tWIRELESS DEAUTH FRAMES" ; delimiter ; tshark -n -r $FILE wlan.fc.type_subtype eq 12 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tWIRELESS PROBE REQUESTS" ; delimiter ; tshark -n -r $FILE -Y "(wlan.fc.type_subtype eq 4)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tWIRELESS PROBE RESPONSES" ; delimiter ; tshark -n -r $FILE -Y "(wlan.fc.type_subtype eq 5)" 2>/dev/null ; delimiter ; IFS=$'\n' ; for code in mgt ctl data ; do if [[ "$code" == "mgt" ]] 2>/dev/null ; then echo -e "\n\t\t\t\tWIRELESS TYPE MANAGEMENT (CODE 0)" ; delimiter ; elif [[ "$code" == "ctl" ]] ; then echo -e "\n\t\t\t\tWIRELESS TYPE CONTROL (CODE 1)" 2>/dev/null ; delimiter ; elif [[ "$code" == "data" ]] 2>/dev/null ; then echo -e "\n\t\t\t\tWIRELESS TYPE DATA (CODE 2)" ; delimiter ; tcpdump -ntS -r $FILE "type $code" 2>/dev/null ; fi ; done ; delimiter 
		fi
		;;
	T)
		echo -e "\n\t\t\t\tChecking for IPv6 Tunnels\n" ; tshark -n -r $FILE teredo 2>/dev/null ; delimiter ; echo ; sudo tcpdump -nnXtS -r $FILE 2>/dev/null ; delimiter
		;;
	Q)
		echo -e "\n\t\t\t\tHOST AND DNS INFORMATION" ; delimiter ; tshark -r $FILE -qz hosts 2>/dev/null | sed -n '4,$ p' | sort -u | uniq -c | sort -nr | head -n -1 ; delimiter ; echo -e "\n\t\t\t\t\t\tDNS TREE" ; delimiter ; tshark -n -r $FILE -qz dns,tree 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\t\tDNS QUERY INFORMATION" ; delimiter ; tshark -n -r $FILE -Y "(udp and udp.dstport == 53)" 2>/dev/null | awk '{ print substr($0, index($0,$2)) }' | sed "s/^/\t/" ; delimiter 
		;;
	t)
		echo -e "\n\t\t\t\t" NETWORK TOP TALKERS FOR IPV4 and IPV6 ; delimiter ; tshark -n -r $FILE -qz ipv6_hosts,tree -qz ip_hosts,tree 2>/dev/null ; delimiter
		;;
	B)
		echo -e "\n\t\t\t\tHTTP BASIC AUTHENTICATION" ; delimiter ; tshark -n -r $FILE -T fields -e ip.src -e ip.dst -e tcp.dstport -e http.authbasic -E header=y 2>/dev/null | column -t |  awk 'NR == 1 || /:/' | awk '{print $0, "\n"}' | awk '!x[$0]++' ; delimiter
		;;
	p)
		echo -e "\n\tALL SYN PACKETS OVER PORT 80\n" ; SYN=$(tshark -n -r $FILE "(tcp.flags == 0x02  && tcp.dstport == 80)" 2>/dev/null | awk -F " " '{print $3"\t"$5"\t"}' | wc -l) ; echo -e "\n\t" THERE ARE $SYN SYN PACKETS ; delimiter ; echo -e "\n\tALL SYN/ACK PACKETS OVER PORT 80\n" ; SYN_ACK=$(tshark -n -r $FILE "(tcp.flags == 0x12 && tcp.srcport == 80)" 2>/dev/null | awk -F " " '{print $3"\t"$5"\t"}' | wc -l) ; echo -e "\n\t" THERE ARE $SYN_ACK SYN/ACK PACKETS ; delimiter ; echo -e "\n\tALL ACK PACKETS OVER PORT 80\n" ; ACK=$(tshark -n -r $FILE "(tcp.flags == 0x10 && tcp.port == 80)" 2>/dev/null | awk -F " " '{print $3"\t"$5"\t"}' | wc -l) ; echo -e "\n\t" THERE ARE $ACK ACK PACKETS ; delimiter ; echo -e "\n\tALL SYN PACKETS OVER PORT 443\n" ; SYN=$(tshark -n -r $FILE "(tcp.flags == 0x02  && tcp.dstport == 443)" 2>/dev/null | awk -F " " '{print $3"\t"$5"\t"}' | wc -l) ; echo -e "\n\t" THERE ARE $SYN SYN PACKETS ; delimiter ; echo -e "\n\tALL SYN/ACK PACKETS OVER PORT 443\n" ; SYN_ACK=$(tshark -n -r $FILE "(tcp.flags == 0x12 && tcp.srcport == 443)" 2>/dev/null | awk -F " " '{print $3"\t"$5"\t"}' | wc -l) ; echo -e "\n\t" THERE ARE $SYN_ACK SYN/ACK PACKETS ;  delimiter ; echo -e "\n\tALL ACK PACKETS OVER PORT 443\n" ; ACK=$(tshark -n -r $FILE "(tcp.flags == 0x10 && tcp.port == 443)" 2>/dev/null | awk -F " " '{print $3"\t"$5"\t"}' | wc -l) ; echo -e "\n\t" THERE ARE $ACK ACK PACKETS ; delimiter 
		;;
	X)
		echo -e "\n\tTOTAL NUMBER OF SYN PACKETS" ; SYN=$(tshark -n -r $FILE tcp.flags == 0x02 2>/dev/null | wc -l) ; echo -e "\n\tThere are $SYN SYN Packets" ; delimiter ; echo -e "\n\tTOTAL NUMBER OF SYN/ACK PACKETS" ; SYN_ACK=$(tshark -n -r $FILE tcp.flags == 0x12 2>/dev/null| wc -l) ; echo -e "\n\tThere are $SYN_ACK SYN/ACK Packets" ; delimiter ; echo -e "\n\tTOTAL NUMBER OF RESET PACKETS" ; RESET=$(tshark -n -r $FILE tcp.flags == 0x04 2>/dev/null | wc -l) ; echo -e "\n\tThere are $RESET RESET Packets" ; delimiter ; echo -e "\n\tTOTAL NUMBER OF URGENT PACKETS" ; URGENT=$(tshark -n -r $FILE tcp.flags == 0x20 2>/dev/null | wc -l) ; echo -e "\n\tThere are $URGENT URGENT Packets" ; delimiter ; echo -e "\n\tTOTAL NUMBER OF PUSH PACKETS" ; PUSH=$(tshark -n -r $FILE tcp.flags == 0x08 2>/dev/null | wc -l) ; echo -e "\n\tThere are $PUSH PUSH Packets" ; delimiter
		;; 
		
	A)
		echo -e "\n\t\t" LOOK FOR SPOOFED PACKETS '(src mac, dst mac, ip.src, ip.dst)' ; delimiter ; tshark -n -r $FILE -T fields -e eth.src -e eth.dst -e ip.src -e ip.dst -E header=y 2>/dev/null | column -t | awk '{print $0, "\n"}' |  awk '!x[$0]++' ; delimiter 
		;;
	W)
		echo -e "\n\t\t\t\tSMB INFORMATION" ; delimiter ; tshark -n -r $FILE -Y "(smb.cmd == 0x73)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tSMB FILE CONTAINS 'EXE'" ; delimiter ; tshark -n -r $FILE -Y "(smb.file contains exe)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tSMB SERVER" ; delimiter ; tshark -n -r $FILE -Y "(smb.server)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tSMB PATH" ; delimiter ; tshark -n -r $FILE -Y "(smb.path)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tSMB PASSWORD" ; delimiter ; tshark -n -r $FILE -Y "(smb.password)" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tSMB PID" ; delimiter ; tshark -n -r $FILE -Y "(smb.pid)" 2>/dev/null ; delimiter ; echo
		;;
	a)
		delimiter ; echo -e "\n\t\t\t\t\tARP REPLY MESSAGES" ; delimiter ; echo ; tshark -n -r $FILE arp.opcode==2 2>/dev/null | awk '{$1=$2=""}1' | sed 's/^/                /' ; delimiter ; echo -e "\n\t\t\t\tARP DUPLICATE FRAMES (ARP POISONING)" ; delimiter ; echo ; tshark -n -r $FILE -Y "(arp.duplicate-address-frame)" 2>/dev/null | sed "s/      //g" | sed 's/^/        /' ; delimiter 
		;;
	f)
		echo -e "\n\t\t\t\tFRAGMENTED PACKETS" ; delimiter ; echo ; tshark -n -r $FILE -Y "(ip.flags.mf == 1) || (ip.frag_offset >= 0x001)" 2>/dev/null | sort -u ; delimiter
		;;
	s)
		echo -e "\n\t\t\tSEARCH FOR STRING" ; delimiter ; tshark -n -r $FILE -qz io,phs 2>/dev/null ; delimiter ; read -p "$cr In what protocol(s) would you like to search for a string? " prot ; shopt -s nocasematch ; read -p "$cr What string would you like to search for? " string ; if [[ "$string" = "$string" ]] ; then delimiter ;  for p in ${prot[@]} ; do for s in ${string[@]} ; do echo -e "\n\t\t\t\tSearching in [ $p ] for [ $s ]" ; delimiter ; for str in ${s[@]} ; do echo ; tshark -n -r $FILE $p matches "$str" 2>/dev/null && tshark -n -r $FILE $p contains "$str" 2>/dev/null ; delimiter ; echo ; done ; done ; done; fi ; shopt -u nocasematch
		;;
	i)
		echo -e "\n\t\t\t\tICMP HOST UNREACHABLE MESSAGES" ; delimiter ; tcpdump -ntS -r $FILE "icmp[0] = 3 and icmp[1] = 1" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\t\tPORT UNREACHABLE" && tcpdump -ntS -r $FILE "icmp[0] = 3 and icmp[1] = 3" 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tICMP PACKETS LARGER THAN 160 BYTES" ; delimiter ; tcpdump -nnXSt -r $FILE "icmp and length > 160" 2>/dev/null ; delimiter
		;;
	c)
		echo -e "\n\t\t\t\tIPv4 and IPv6 CONVERSATIONS\n" ; delimiter ; tshark -n -r $FILE -qz conv,ipv6 -qz conv,ip 2>/dev/null ; delimiter
		;;
	P)
		echo -e "\n\t\tPROTOCOL HIERARCHY STATISTICS" ; delimiter ; tshark -r $FILE -qz io,phs 2>/dev/null ; delimiter
		;;
	F)
		VAR=$OPTARG
		if [[ $VAR = -tcp ]]
		then LEN=$(tshark -n -r $FILE -qz conv,tcp 2>/dev/null | awk 'NR>=6' | awk '{print $1,seq=","$3}' | sed 's/ ,/,/' | sed '/:443/d' | sed ' /:22/d' | awk '!x[$0]++' | wc -l)
		if (( $LEN <= 1 ))
		then echo -e "\nNO TCP STREAMS FOUND WITHIN $FILE\n" ; delimiter
		else
		delimiter ; tshark -n -r $FILE -qz conv,tcp 2>/dev/null | awk 'NR>=6' | awk '{print $1,seq=","$3}' | sed 's/ ,/,/' | sed '/:443/d' | sed '/:22/d' | awk '!x[$0]++' ; delimiter 
		read -p "$cr Enter the TCP stream you would like to follow: " follow
		delimiter
		read -p "$cr Would you like to save stream to a file? (y/N) " stream
		filename="tcp_stream.txt"
		if [[ "$stream" = ["y","Y"] ]]
		then
		tshark -n -r $FILE -qz follow,tcp,ascii,$follow 2>/dev/null | awk '!x[$0]++' >/dev/null 2>&1 > $filename ; echo -e "\nMake sure to delete the header and footer information from file $filename.\n\nIf base64 encoded, Run [ cat $filename | perl -p -e 's/\R//g;' > out-file.txt ] to fix any line errors that may occur." ; delimiter
		else
		echo -e "\n\t\t\tFOLLOW TCP STREAM [ $follow ]" ; delimiter ; tshark -n -r $FILE -qz follow,tcp,ascii,$follow 2>/dev/null | awk '!x[$0]++' 2>/dev/null ; delimiter
		fi
		fi
		fi

		if [[ $VAR = -udp ]]
		then LEN=$(echo ; tshark -n -r $FILE -qz conv,udp 2>/dev/null | awk 'NR>=6' | awk '{print$1,seq=","$3}' | sed 's/ ,/,/' | wc -l)
		if (( $LEN <= 1 ))
		then echo -e "\nNO UDP STREAMS FOUND WITHIN $FILE\n" ; delimiter
		else
		read -p "$cr Enter the UPD Stream you would like to follow: " follow
		delimiter
		echo -e "\n\t\t\tFOLLOW UDP STREAM [ $follow ]" ; delimiter ; tshark -n -r $FILE -qz follow,udp,ascii,$follow 2>/dev/null | awk '!x[$0]++' ; delimiter
		fi
		fi
		if [[ $VAR = -http ]]
		then LEN=$(echo ; tshark -n -r $FILE -qz conv,tcp 2>/dev/null | awk 'NR>=6' | awk '{print $1,seq=","$3}' | sed 's/ ,/,/' | grep ":80\$" | wc -l)
		if (( $LEN <= 1 ))
		then
		echo -e "\nNO HTTP STREAMS FOUND WITHIN $FILE" ; delimiter
		else
		delimiter ; tshark -n -r $FILE -qz conv,tcp 2>/dev/null | awk 'NR>=6' | awk '{print $1,seq=","$3}' | sed 's/ ,/,/' | grep -v ":22" | grep -v ":443" ; echo -e "\n[ Copy any line from above and paste below ]\n"
		read -p "$cr Enter the HTTP Stream you would like to follow: " follow
		delimiter 
		read -p "$cr Would you like to save http stream to a file? (y/N) " stream
		filename="http_stream.txt"
		if [[ "$stream" = ["y","Y"] ]]
		then
		tshark -n -r $FILE -qz follow,http,ascii,$follow 2>/dev/null > $filename; delimiter ; echo -e "\nFilename saved in $PWD as $filename\n" ; delimiter
		else
		echo -e "\n\t\t\tFOLLOW HTTP STREAM [ $follow ]" ; delimiter ; tshark -n -r $FILE -qz follow,http,ascii,$follow 2>/dev/null ; delimiter
		fi
		fi
		fi
		;;

	l)
		echo -e "\n\t\t\t\tPACKET LENGTHS" ; delimiter ; tshark -r $FILE -qz plen,tree 2>/dev/null ; delimiter
		;;
	L)
		echo -e "\n\t\t\t\tPACKETS GREATER THAN 1280 BYTES"; delimiter ; echo ; tshark -n -r $FILE "tcp.len > 1280" 2>/dev/null | grep -ie http | sed 's/\(.*\)/              \1/'; delimiter
		;;
	H)
		echo -e "\n\t\t\t\tHTTP REQUESTS FROM HOST" ; delimiter ; tshark -n -r $FILE -qz http_req,tree 2>/dev/null ; delimiter ; echo -e "\n\t\t\t\tHTTP SERVER REQUESTS" ; delimiter ; tshark -n -r $FILE -qz http_srv,tree 2>/dev/null ; delimiter
		;;
	R)
		echo -e "\n\t\t\t\tHTTP GET REQUESTS" ; delimiter ; echo ; tshark -n -r $FILE http.request.method == GET 2>/dev/null | awk '{ print substr($0, index($0,$3)) }' | column -t | sed 's/\(.*\)/              \1/' ; delimiter ; echo -e "\n\t\t\t\tHTTP POST REQUESTS" ; delimiter ; echo ; tshark -n -r $FILE http.request.method == POST 2>/dev/null | awk '{ print substr($0, index($0,$3)) }' | column -t | sed 's/\(.*\)/              \1/' ; delimiter
		;; 
	x)
		echo -e "\n\t\t\t\tEXPORT OBJECTS" ; delimiter ; tshark -n -r $FILE -qz io,phs 2>/dev/null ; delimiter ; echo -e "\nProtocols you can export objects from are listed below. Verify protocol is listed above.\n\ndicom\nhttp\nimf\nsmb\ntftp" ; read -p "$cr Is your protocol listed above? (y/N) " verify ; if [[ "$verify" = ["Y","y"] ]]; then read -p "$cr Which protocol would you like to export objects from? " export ;  tshark -n -r $FILE --export-objects $export,$export\-Dump >/dev/null 2>&1; echo -e "\nExported Objects saved to $export-Dump (*NOTE: Directory $export-Dump may not contain any exported data because no data was able to be extracted)" ; else echo -e "\nPROTOCOL NOT LISTED." ; fi ; delimiter
		;;
	U)
		# Grepping out Most common UDP ports
		PROT=$OPTARG
		if [[ $PROT = -udp ]]
		then
		echo -e "\n\t\t\t\tUNCOMMON UDP PORTS\n" ; delimiter ; tshark -n -r $FILE -qz conv,udp 2>/dev/null | grep -v ":1 " | grep -v ":7 " | grep -v ":22 " | grep -v ":37 " | grep -v ":42 " | grep -v ":49 " | grep -v ":53 " | grep -v ":56 " | grep -v ":67 " | grep -v ":68 " | grep -v ":68 " | grep -v ":69 " | grep -v ":123 " | grep -v ":161 " | grep -v ":80 " | grep -v ":88 " | grep -v ":113 " | grep -v ":135 " | grep -v ":137 " | grep -v ":138 " | grep -v ":139 " | grep -v ":143 " | grep -v ":177 " | grep -v ":194 " | grep -v ":220 " | grep -v ":264 " | grep -v ":389 " | grep -v ":427 " | grep -v ":464 " | grep -v ":500 " | grep -v ":514 " | grep -v ":520 " | grep -v ":593 " | grep -v ":631 " | grep -v ":636 " | grep -v ":639 " | grep -v ":666 " | grep -v ":698 " | grep -v ":749 " | grep -v ":750 " | grep -v ":751 " | grep -v ":752 " | grep -v ":753 " | grep -v ":754 " | grep -v ":901 " | grep -v ":902 " | grep -v ":903 " | grep -v ":904 " | grep -v ":989 " | grep -v ":990 " | grep -v ":992 " | grep -v ":1234 " | grep -v ":1434 " | grep -v ":1512 " | grep -v ":1701 " | grep -v ":1723 " | grep -v ":1755 " | grep -v ":1812 " | grep -v ":2049 " | grep -v ":2483 " | grep -v ":2488 " | grep -v ":3074 " | grep -v ":3306 " | grep -v ":3389 " | grep -v ":3544 " | grep -v ":3690 " | grep -v ":3723 " | grep -v ":3784 " | grep -v ":3785 " | grep -v ":4116 " | grep -v ":4500 " | grep -v ":5001 " | grep -v ":5004 " | grep -v ":5005 " | grep -v ":5351 " | grep -v ":5353 " | grep -v ":5355 " | grep -v ":5432 " | grep -v ":5900 " | grep -v ":6346 " | grep -v ":7648 " | grep -v ":7649 " ; delimiter 
		# Grepping out Most common TCP ports
		elif [[ $PROT = -tcp ]]
		then
		echo -e "\n\t\t\t\tUNCOMMON TCP PORTS\n" ; delimiter ; tshark -n -r $FILE -qz conv,tcp 2>/dev/null | grep -v ":1 " | grep -v ":7 " | grep -v ":22 " | grep -v ":37 " | grep -v ":42 " | grep -v ":49 " | grep -v ":53 " | grep -v ":56 " | grep -v ":67 " | grep -v ":68 " | grep -v ":68 " | grep -v ":69 " | grep -v ":123 " | grep -v ":161 " | grep -v ":80 " | grep -v ":88 " | grep -v ":113 " | grep -v ":135 " | grep -v ":137 " | grep -v ":138 " | grep -v ":139 " | grep -v ":143 " | grep -v ":177 " | grep -v ":194 " | grep -v ":220 " | grep -v ":264 " | grep -v ":389 " | grep -v ":427 " | grep -v ":464 " | grep -v ":500 " | grep -v ":514 " | grep -v ":520 " | grep -v ":593 " | grep -v ":631 " | grep -v ":636 " | grep -v ":639 " | grep -v ":666 " | grep -v ":698 " | grep -v ":749 " | grep -v ":750 " | grep -v ":751 " | grep -v ":752 " | grep -v ":753 " | grep -v ":754 " | grep -v ":901 " | grep -v ":902 " | grep -v ":903 " | grep -v ":904 " | grep -v ":989 " | grep -v ":990 " | grep -v ":992 " | grep -v ":1234 " | grep -v ":1434 " | grep -v ":1512 " | grep -v ":1701 " | grep -v ":1723 " | grep -v ":1755 " | grep -v ":1812 " | grep -v ":2049 " | grep -v ":2483 " | grep -v ":2488 " | grep -v ":3074 " | grep -v ":3306 " | grep -v ":3389 " | grep -v ":3544 " | grep -v ":3690 " | grep -v ":3723 " | grep -v ":3784 " | grep -v ":3785 " | grep -v ":4116 " | grep -v ":4500 " | grep -v ":5001 " | grep -v ":5004 " | grep -v ":5005 " | grep -v ":5351 " | grep -v ":5353 " | grep -v ":5355 " | grep -v ":5432 " | grep -v ":5900 " | grep -v ":6346 " | grep -v ":7648 " | grep -v ":7649 " | grep -v ":20 " | grep -v ":21 " | grep -v ":23 " | grep -v ":25 " | grep -v ":43 " | grep -v ":79 " | grep -v ":81 " | grep -v ":82 " | grep -v ":110 " | grep -v ":115 " | grep -v ":119 " | grep -v ":179 " | grep -v ":443 " | grep -v ":8443 " | grep -v ":445 " | grep -v ":465 " | grep -v ":512 " | grep -v ":513 " | grep -v ":515 " | grep -v ":540 " | grep -v ":691 " | grep -v ":873 " | grep -v ":993 " | grep -v ":995 " | grep -v ":1025 " | grep -v ":1026 " | grep -v ":1029 " | grep -v ":1080 " | grep -v ":1214 " | grep -v ":1337 " | grep -v ":1433 " | grep -v ":1521 " | grep -v ":2967 " | grep -v ":4321 " | grep -v ":5800 " | grep -v ":6129 " | grep -v ":6660 " | grep -v ":6661 " | grep -v ":6662 " | grep -v ":6663 " | grep -v ":6664 " | grep -v ":6665 " | grep -v ":6666 " | grep -v ":6667 " | grep -v ":6668 " | grep -v ":6669 " | grep -v ":6679 " | grep -v ":6697 " | grep -v ":6891 " | grep -v ":6892 " | grep -v ":6893 " | grep -v ":6894 " | grep -v ":6895 " | grep -v ":6896 " | grep -v ":6897 " | grep -v ":6898 " | grep -v ":6899 " | grep -v ":6900 " | grep -v ":6901 " | grep -v ":8008 " | grep -v ":8080 " | grep -v ":8500 " | grep -v ":9050 " | grep -v ":9051 " ; delimiter
		fi
		;;		
	h)
		help ; exit 0
		;;
		
esac
done
shift $((OPTIND-1))
shift
done

