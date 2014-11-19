import mysocket, time

serverPort = 12000
serverSocket = mysocket.mysocket()
# serverSocket.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1)
serverSocket.bind(('',serverPort))
serverSocket.listen(1)
print 'The server is ready to receive'
# while 1:
connectionSocket, addr = serverSocket.accept()
while 1:
	sentence = connectionSocket.recv(1024)
	if len(sentence) == 0:
		break;
	print "Received: " + sentence
	capitalizedSentence = sentence.upper()
	connectionSocket.send(capitalizedSentence)
connectionSocket.close()
