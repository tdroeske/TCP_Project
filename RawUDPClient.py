
import socket, sys
from struct import *
 

source_ip = '128.119.74.85'
dest_ip = '192.241.166.195'		# Wireshark: ip.dst == 192.241.166.195 or ip.src == 192.241.166.195
 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    s.bind(('', 1234)) # Doesn't work
    print s.getsockname() # Prints out false info
    
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()


# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_UDP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton (source_ip)   
ip_daddr = socket.inet_aton (dest_ip)
 
ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
 

# udp header fields
source_port = 1234
dest_port = 12000
length = 0
checksum = 0

user_data = "Hello World"
length = len(user_data.encode('utf-8')) + calcsize("!HHHH")
udp_header = pack("!HHHH" , source_port, dest_port, length, checksum)


 
# final full packet
packet = ip_header + udp_header + user_data
 

#Send the packet
bytes = s.sendto(packet, (dest_ip , 0 ))
print "Bytes sent: " + str(bytes)

modifiedMessage, serverAddress = s.recvfrom(4096) # Hangs here	# Block ICMP: iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP
print modifiedMessage









