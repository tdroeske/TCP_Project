import mysocket, time


sock = mysocket.mysocket()

sock.connect(['192.241.166.195', 12000])
time.sleep(3)
sock.send("Hello World!")
modifiedSentence = sock.recv(65535)
print modifiedSentence
time.sleep(3)
sock.close()