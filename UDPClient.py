import socket


serverName = "192.241.166.195"
serverPort = 12000
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while 1:
	message = raw_input("Input lowercase sentence: ")
	clientSocket.sendto(message,(serverName, serverPort))
	modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
	print modifiedMessage
clientSocket.close()