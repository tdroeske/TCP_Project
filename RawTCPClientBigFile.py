import mysocket, time


sock = mysocket.mysocket()

sock.connect(['192.241.166.195', 12000])

count = 0

with open("aladdin.txt") as file:
    for line in file:
    	sock.send(line)
    	count += 1
print "file closed"
sock.close()
print count




