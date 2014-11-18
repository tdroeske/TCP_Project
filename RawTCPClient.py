import mysocket, time


sock = mysocket.mysocket()

sock.connect(['192.241.166.195', 12000])
time.sleep(5)
# sock.send("Hello World!")
sock.send("Test Message One")	# Check length of strings
sock.send("Test Message Two")
sock.send("Test Message Three")
time.sleep(1)
sock.send("Test Message Four!")
sock.send("Test Message Five!")
modifiedSentence = sock.recv(65535)
print ""
print "Response:", modifiedSentence
print ""
modifiedSentence = sock.recv(65535)
print ""
print "Response:", modifiedSentence
print ""
time.sleep(5)
sock.close()