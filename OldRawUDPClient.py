import socket, sys
from struct import *


serverName = "192.241.166.195"
# serverPort = 12000

# udp header fields
source_port = 1234
dest_port = 12000
length = 0
checksum = 0

data = "Hello World"
length = len(data.encode('utf-8')) + calcsize("!HHHH")
header = pack("!HHHH" , source_port, dest_port, length, checksum)

header_check = unpack("!HHHH", header)
print header_check
# print calcsize("!HHHH") # Should be 8

# make udp packet
packet = header + data


try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + '. Message: ' + msg[1]
	sys.exit()

# Include IP headers
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
print serverName, dest_port
bytes = sock.sendto(packet,(serverName, dest_port))
print bytes
# modifiedMessage, serverAddress = sock.recvfrom(4096)
# print modifiedMessage


'''
while 1:
	message = raw_input("Input lowercase sentence: ")
	clientSocket.sendto(message,(serverName, serverPort))
	modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
	print modifiedMessage
clientSocket.close()
'''
























