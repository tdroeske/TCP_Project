import mysocket, time

serverSocket = mysocket.mysocket()
serverPort = 12000
serverSocket.bind(('',serverPort))
serverSocket.listen(1)
print 'The server is ready to receive'
# while 1:
connectionSocket, addr = serverSocket.accept()
count = 0
while 1:
	sentence = connectionSocket.recv(1024)
	if len(sentence) == 0:
		break;
	print sentence
	count += 1
connectionSocket.close()
print count
