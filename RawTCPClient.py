import mysocket, time


sock = mysocket.mysocket()

sock.connect(['192.241.166.195', 12000])
time.sleep(5)
sock.send("Hello World!")
modifiedSentence = sock.recv(65535)
print ""
print "Response:", modifiedSentence
print ""
time.sleep(5)
sock.close()