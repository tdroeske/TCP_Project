import mysocket, time


sock = mysocket.mysocket()

sock.connect(['192.241.166.195', 12000])

with open("aladdin.txt") as file:	# Use file to refer to the file object
    line = file.read()
    sock.send(line)

sock.close()



