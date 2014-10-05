
import socket, sys
from struct import *
 

source_ip = '72.19.81.57'
dest_ip = '192.241.166.195'		# Wireshark: ip.dst == 192.241.166.195 or ip.src == 192.241.166.195
 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    s.bind(('', 1234)) # Doesn't work
    # print s.getsockname() # Prints out false info
    
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()


# ip header fields
ip_ver = 4
ip_ihl = 5
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
 
while 1:
	# udp header fields
	source_port = 1234
	dest_port = 12000
	length = 0
	checksum = 0

	user_data = raw_input("Input lowercase sentence: ")
	# user_data = "Hello World"
	length = len(user_data.encode('utf-8')) + calcsize("!HHHH")
	udp_header = pack("!HHHH" , source_port, dest_port, length, checksum)


	 
	# final full packet
	packet = udp_header + user_data	# This only works when I don't add in the IP header fields
	 

	#Send the packet
	bytes = s.sendto(packet, (dest_ip , 0 ))
	# print "Bytes sent: " + str(bytes)
	server_ip = 0
	count = 10 		# Will look at 10 packets until giving up
	while 1:
		modifiedMessage, serverAddress = s.recvfrom(4096)
		server_ip = socket.inet_ntoa(modifiedMessage[12:16])
		if server_ip == dest_ip:
			break
		count-=1
		if count == 0:
			break
		# print server_ip

	# print len(modifiedMessage)
	if count != 0:
		# print modifiedMessage
		print modifiedMessage[28:]	# 20 bytes for IP header and 8 bytes for UDP header
	else:
		print "Did not receive response"










