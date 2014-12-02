import socket, sys, time
from random import randint
from struct import *
import array
import threading
import Queue
import copy
 
# Block ICMP: "sudo iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP"  <-- 3 is specific to Port Unreachable message
# Disable RST Packets: "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 72.19.80.211 -j DROP"  <-- Use src IP
# Enable Promiscuous mode: "sudo ifconfig wlan0 promisc"
# Wireshark: ip.dst == 192.241.166.195 or ip.src == 192.241.166.195

class mysocket:

    def __init__(self):
        self.sock = ''
        self.src_ip = '72.19.80.211'
        self.src_port = randint(1024, 65535)
        self.dest_ip = "0.0.0.0"
        self.dest_port = 0
        self.timeout = 0
        self.connOpen = False

        self.currentOutbound = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        self.currentInbound = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)

        self.estimatedRTT = 1
        self.devRTT = 0
        self.timeoutinterval = 1

        self.threadsOpen = True
        self.recvQueue = []  # Used when the application layer calls recv()
        # self.recvstart = 0
        self.recvend = 0

        self.sendQueue = []  # Used to send a packet
        self.inboundQueue = []   # Used to store packets and add to the recvQueue when they are in order
        self.outboundQueue = []  # Used to store unacknowledged packets

        self.recvthread = threading.Thread(target=self.__recvloop)
        self.sendthread = threading.Thread(target=self.__sendloop)
        self.sendBase = 0; # Oldest unacknowledged byte     # TODO Update this accordingly
        self.nextseqnum = 0;
        self.nextseqnumsent = 0;
        self.nextacknum = 0;
        # self.recvthread.start()
        # time.sleep(1)
        # self.src_ip = '192.168.1.1'

        self.inboundrecvwin = 0
        self.lastbytesent = 0
        self.lastbyteacked = 0
        self.outboundrecvwin = 12840
        self.duplicateacks = 0

        self.mss = 1386
        self.cwnd = self.mss
        self.ssthresh = 0

        self.finsent = False
        self.finrecvd = False

        self.printlock = threading.Lock()
        # self.sendlock = threading.Lock()

    def accept(self):
        # print self.src_port
        while 1:  
                response, addr = self.sock.recvfrom(65535)
                # print "From accept()", self.src_ip
                respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
                respPack.extractData(response)

                # print respPack.dest_address, ",", self.src_ip, "," , respPack.tcp_dest, "," , self.src_port
                if respPack.dest_address == self.src_ip and respPack.tcp_dest == self.src_port:
                    # printlog("Received proper packet")
                    pack = packet(self.src_ip, self.src_port, respPack.source_address, respPack.tcp_source)
                    pack.tcp_seq = randint(0, 2**32)
                    self.__printPacket(respPack)
                    self.dest_ip = respPack.source_address
                    self.dest_port = respPack.tcp_source
                    if respPack.tcp_syn:
                        break
                    else:
                        pack.tcp_rst = 1
                    self.__sendpacket(pack)

        # Send syn ack packet
        pack.tcp_syn = 1
        pack.tcp_ack = 1
        pack.tcp_ack_seq = respPack.tcp_seq + 1
        # self.sendBase = pack.tcp_seq
        self.__sendpacket(pack)

        # Receive ack
        self.__recvpacket()

        self.sendBase = pack.tcp_seq
        self.nextseqnum = pack.tcp_seq + 1
        self.nextseqnumsent = pack.tcp_seq + 1
        self.nextacknum = pack.tcp_ack_seq

        self.connOpen = True
        self.sendthread.start()
        self.recvthread.start() 

        return self, respPack.source_address

    def bind(self, address): # TODO
        ip, port = address
        if len(ip) > 0:
            self.src_ip = ip
        self.src_port = port
        # self.src_ip, self.src_port = address

    def close(self):
        # self.threadsOpen = False

        # send fin packet
        pack = self.currentOutbound
        pack.resetflags()
        pack.tcp_fin = 1;
        pack.tcp_ack = 1;
        pack.tcp_seq = self.nextseqnumsent
        pack.user_data = ""
        if not self.finsent and not self.finrecvd:
            self.__sendpacket(pack)
            self.finsent = True
            self.nextseqnumsent += 1

        # receive ack packet
        # self.__recvpacket()

        # receive fin packet
        # self.__recvpacket()

        # send ack packet
        # pack = self.currentOutbound
        # pack.resetflags()
        # pack.tcp_ack = 1
        # pack.tcp_seq += 1
        # pack.tcp_ack_seq += 1
        # self.__sendpacket(pack)

        # self.connOpen = False

    def connect(self, address):
        #create a raw socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        self.dest_ip = address[0]
        self.dest_port = address[1]

        # Send syn packet
        pack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        pack.tcp_syn = 1
        pack.tcp_seq = randint(0, 2**32)
        # self.sendBase = pack.tcp_seq
        self.__sendpacket(pack)

        # Receive syn ack packet
        self.__recvpacket()
        self.nextacknum = self.currentInbound.tcp_seq+1
        self.connOpen = True

        # send ack packet
        self.__sendack()

        self.sendBase = pack.tcp_seq
        self.nextseqnum = pack.tcp_seq
        self.nextseqnumsent = pack.tcp_seq

        self.sendthread.start()
        self.recvthread.start()        

    def getpeername(self):
        return self.dest_ip, self.dest_port

    def sockName(self):
        return self.src_ip, self.src_port

    def listen(self, backlog):
        #create a raw socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

    def recv(self, bufsize):
        # # receive push packet
        # while 1:
        #     self.__recvpacket()
        #     if self.currentInbound.tcp_psh:
        #         break

        # # send ack packet
        # self.__sendack()
        # return self.currentInbound.user_data
        
        while 1:
            if self.recvend > 0:
                pack = self.recvQueue.pop(0)
                data = pack.user_data
                # self.recvstart += 1
                self.recvend -= 1
                self.outboundrecvwin += len(data)
                return data
            # else:
            #     printlog("no data to receive")


    def recvfrom(self, bufsize):
        return self.recv(bufsize), self.dest_ip

    def send(self, data):
        # send data with push ack
        # pack = self.currentOutbound
        pack = copy.deepcopy(self.currentOutbound)
        pack.resetflags()
        pack.tcp_psh = 1;
        pack.tcp_ack = 1;
        pack.tcp_seq = self.nextseqnum
        pack.user_data = data
        
        # print "Sending", pack.user_data
        # start = time.time()
        self.sendQueue.append(pack)

        self.nextseqnum += len(data)
        # receive ack
        # self.__recvpacket()
        # end = time.time()
        # self.__calculatetimeout(end-start)

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout


    def __sendpacket(self, pack):
        if self.connOpen or pack.tcp_syn:
            pack.tcp_window = self.outboundrecvwin
            pack.createpacket()
            bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
            pack.timesent = time.time()
            self.__printPacket(pack)
            # pack.tcp_seq += len(pack.user_data)
            self.currentOutbound = pack
            self.nextseqnumsent += len(pack.user_data)
            

    def __recvpacket(self):
        if self.connOpen or self.currentOutbound.tcp_syn:
            while 1:  
                response, addr = self.sock.recvfrom(65535)
                respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
                respPack.extractData(response)
                if respPack.source_address == self.dest_ip and respPack.dest_address == self.src_ip and respPack.tcp_source == self.dest_port and respPack.tcp_dest == self.src_port:
                    self.__printPacket(respPack)
                    break

            
            if self.__validatePacket(respPack):
                self.currentInbound = respPack
                # return None
                # print ""
                # print "invalid packet"
                # print ""
            # print len(response)
            # print respPack.user_data
            self.inboundrecvwin = respPack.tcp_window
            # self.currentOutbound.tcp_ack_seq += len(self.currentInbound.user_data)
            return respPack

    def __validatePacket(self, pack):

        if not pack.correctchecksum:
            return False

        # if ack received
        if pack.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin:
            self.__ackrecvd(pack)

        # if fin ack received, close connection
        if self.currentInbound.tcp_fin:
            self.__finrecvd()

        return True

        # # if syn sent, expect syn ack
        # if self.currentOutbound.tcp_syn:
        #     # print "invalid packet: syn sent, expected syn ack"
        #     return self.currentInbound.tcp_syn and self.currentInbound.tcp_ack

        # # if psh ack sent, expect ack
        # # if self.currentOutbound.tcp_psh and self.currentOutbound.tcp_ack:
        # #     print "invalid packet: psh ack sent, expected ack"
        # #     return self.currentInbound.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin

        # # if fin ack sent, expect ack
        # if self.currentOutbound.tcp_fin and self.currentOutbound.tcp_ack:
        #     # print "invalid packet: fin ack sent, expected ack"
        #     return self.currentInbound.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin

    def __sendack(self):
        # send ack packet
        pack = self.currentOutbound

        if self.currentInbound.tcp_psh:
            pack.tcp_ack_seq = self.nextacknum
            pack.tcp_seq = self.nextseqnumsent

        if self.currentInbound.tcp_syn and self.currentInbound.tcp_ack:
            pack.tcp_seq +=1
            pack.tcp_ack_seq = self.currentInbound.tcp_seq+1

        if self.currentInbound.tcp_fin and self.currentInbound.tcp_ack:
            # pack.tcp_seq +=1
            pack.tcp_seq = self.nextseqnumsent
            pack.tcp_ack_seq = self.currentInbound.tcp_seq+1

        pack.resetflags()
        pack.tcp_ack = 1
        pack.user_data = ""
        self.__sendpacket(pack)
        # self.sendQueue.append(pack)

    def __ackrecvd(self, pack):
        printlog("ack received")


        if pack.tcp_ack_seq > self.sendBase:
            self.sendBase = pack.tcp_ack_seq
            self.duplicateacks = 0
            '''
            if (there are currently any not-yet-acknowledged segments)
                start timer
            }
            '''
        else:   # duplicate ack received
            self.duplicateacks += 1
            if self.duplicateacks >=3:  # Fast retransmit
                self.sendQueue.insert(0, self.outboundQueue[0])
                self.duplicateacks = 0

        # Removes packets that have now been acked
        for p in  self.outboundQueue:
            if p.tcp_seq < pack.tcp_ack_seq:
                self.outboundQueue.pop(0)

        self.lastbyteacked = pack.tcp_ack_seq


    def __finrecvd(self):
        printlog("Fin received") 
                             
        # fin ack received
        self.finrecvd = True
        # pack = self.currentOutbound
        # inpack = self.currentInbound
        # pack.resetflags()
        # pack.tcp_ack = 1
        # self.__sendpacket(pack)

        self.__sendack()
        # self.threadsOpen = False

        # add a dummy packet to recvQueue which returns data of length zero
        pack = copy.deepcopy(self.currentOutbound)
        pack.user_data = ''
        self.recvQueue.append(pack)
        self.recvend += 1

        # if we didn't initiate the close connection, then respond with an ack (done above), then a fin ack
        if not self.finsent:
            # send ack packet
            # pack.resetflags()
            # pack.tcp_ack = 1
            # pack.tcp_seq += 1
            # pack.tcp_ack_seq = inpack.tcp_seq + 1
            # print "Acking the unexpected Fin Ack"
            # self.__sendack()


            # send fin ack packet
            pack.resetflags()
            pack.tcp_fin = 1
            pack.tcp_ack = 1
            pack.tcp_seq = self.nextseqnumsent
            pack.user_data = ""
            self.__sendpacket(pack)
            self.finsent = True
            self.nextseqnumsent += 1

            # receive ack packet
            # self.__recvpacket()

        self.connOpen = False
        self.threadsOpen = False

    def __calculatetimeout(self, sampleRTT):
        self.estimatedRTT = 0.875 * self.estimatedRTT + 0.125 * sampleRTT   # pg. 239
        self.devRTT = 0.75 * self.devRTT + 0.25 * abs(sampleRTT - self.estimatedRTT)     # pg. 240
        self.timeoutinterval = self.estimatedRTT + 4 * self.devRTT


    def __recvloop(self):
        self.sock.setblocking(0)
        printlog("Entering recvloop")
        while self.threadsOpen:
            try:
                self.__recvpacket()
            
                if self.currentInbound.tcp_psh:
                    seen = False
                    # for pack in self.recvQueue:
                    #     if pack.tcp_seq == self.currentInbound.tcp_seq:
                    #         seen = True
                    # if self.currentInbound.tcp_seq < self.nextacknum:
                            # seen = True
                    if self.currentInbound.tcp_seq >= self.nextacknum: # not seen
                        self.recvQueue.append(self.currentInbound)
                        printlog("Added packet to recvQueue")
                        if self.currentInbound.tcp_seq == self.nextacknum:
                            self.recvend += 1 # TODO this needs to be incremented to the 1 after the last in-order packet, not always 1, use while loop
                            self.outboundrecvwin -= len(self.currentInbound.user_data)
                            printlog("recvend incremented")
                        else:
                            printlog("Out of order packet")
                        self.nextacknum = self.currentInbound.tcp_seq + len(self.currentInbound.user_data)
                    else:
                        pass
                        printlog("Duplicate packet received")

                    self.__sendack()
            except:
                pass
        self.sock.setblocking(1)
        printlog("recvloop done")

    def __sendloop(self):
        while self.threadsOpen:
            if not len(self.sendQueue) == 0 and self.lastbytesent - self.lastbyteacked <= self.inboundrecvwin:
                pack = self.sendQueue.pop(0)
                if pack.tcp_psh:
                    self.outboundQueue.append(pack)
                    self.lastbytesent = pack.tcp_seq + len(pack.user_data)
                # print "Sending", pack.user_data
                self.__sendpacket(pack)
        printlog("sendloop done")

    def __printPacket(self, pack):
        self.printlock.acquire()
        pack.printPacket()
        self.printlock.release()

class packet:

    def __init__(self, source_ip, source_port, dest_ip, dest_port):
        self.packet = ""
        self.ip_header = ""
        self.tcp_header = ""
        self.totlength = ""
        self.user_data = ""

        # tcp header fields
        self.tcp_source = source_port   # source port
        self.tcp_dest = dest_port   # destination port
        self.tcp_seq = 454
        self.tcp_ack_seq = 0
        self.tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        self.tcp_fin = 0
        self.tcp_syn = 0
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        # self.tcp_window = socket.htons (5840)
        self.tcp_window = 12840    #   maximum allowed window size
        self.tcp_check = 0
        self.tcp_urg_ptr = 0

        # pseudo header fields
        try:
            # print source_ip, len(source_ip)
            self.source_address = socket.inet_aton(source_ip)
        except:
            self.source_address = socket.inet_aton("0.0.0.0")
        self.dest_address = socket.inet_aton(dest_ip)
        self.placeholder = 0
        self.protocol = socket.IPPROTO_TCP

        self.timesent = 0
        self.correctchecksum = False    # Used when reading received packets

    def makeTCPheader(self):
        self.tcp_offset_res = (self.tcp_doff << 4) + 0
        self.tcp_flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh <<3) + (self.tcp_ack << 4) + (self.tcp_urg << 5)

        # the ! in the pack format string means network order
        if self.tcp_check == 0:
            self.tcp_header = pack('!HHLLBBHHH' , self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, self.tcp_offset_res, self.tcp_flags,  self.tcp_window, self.tcp_check, self.tcp_urg_ptr)
        else:
            # checksum is NOT in network byte order
            self.tcp_header = pack('!HHLLBBH' , self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, self.tcp_offset_res, self.tcp_flags,  self.tcp_window) + pack('H' , self.tcp_check) + pack('!H' , self.tcp_urg_ptr)
        return self.tcp_header

    def resetflags(self):
        self.tcp_fin = 0
        self.tcp_syn = 0
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0

    def createpacket(self):
        self.tcp_check = 0
        # self.tcp_window = socket.htons(self.tcp_window)
        self.makeTCPheader()
        self.tcp_length = len(self.tcp_header) + len(self.user_data)
        self.totlength = 20 + self.tcp_length

        psh = pack('!4s4sBBH' , self.source_address , self.dest_address , self.placeholder , self.protocol , self.tcp_length);
        psh = psh + self.tcp_header + self.user_data;
         
        self.tcp_check = self.checksum(psh)

        self.packet = self.makeTCPheader() + self.user_data

    def checksum(self, pkt):  # <- This one works too
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff

    def extractData(self, dataPack):
        #   B = 1 byte
        #   H = 2 bytes
        #   L = 4 bytes

        self.totlength = len(dataPack)
        # ipheadlength = (unpack('!B', dataPack[0])[0] << 60) >> 60
        # print ipheadlength
        self.ip_totlength = unpack('!B', dataPack[1:2])[0]
        # print "ip total length:" , self.ip_totlength
        # print (unpack('!B', dataPack[0])[0] >> 4) << 4
        # print (unpack('!B', dataPack[0])[0] >> 4) << 4 ^ unpack('!B', dataPack[0])[0]

        self.source_address = socket.inet_ntoa(dataPack[12:16])
        self.dest_address = socket.inet_ntoa(dataPack[16:20])

        self.tcp_source =  unpack('!H', dataPack[20:22])[0]
        self.tcp_dest =  unpack('!H', dataPack[22:24])[0]

        self.tcp_seq = unpack('!L', dataPack[24:28])[0]
        self.tcp_ack_seq = unpack('!L', dataPack[28:32])[0]
        self.tcp_doff = unpack('!B', dataPack[32:33])[0] >> 2

        self.tcp_flags = unpack('!B', dataPack[33:34])[0]
        self.tcp_fin = (self.tcp_flags & 1) != 0
        self.tcp_syn = (self.tcp_flags & 2) != 0
        self.tcp_rst = (self.tcp_flags & 4) != 0
        self.tcp_psh = (self.tcp_flags & 8) != 0
        self.tcp_ack = (self.tcp_flags & 16) != 0
        self.tcp_urg = (self.tcp_flags & 32) != 0

        self.tcp_window = unpack('!H', dataPack[34:36])[0]
        self.tcp_check = unpack('H', dataPack[36:38])[0]
        self.tcp_urg_ptr = unpack('!H', dataPack[38:40])[0]

        self.user_data = dataPack[40:]



        dataPack = dataPack[:36] + pack('H' , 0) + dataPack[38:]
        self.tcp_header = dataPack[20:40]
        self.tcp_offset_res = (self.tcp_doff << 4) + 0
        self.tcp_length = len(self.tcp_header) + len(self.user_data)

        psh = pack('!4s4sBBH' , socket.inet_aton(self.source_address) , socket.inet_aton(self.dest_address) , self.placeholder , self.protocol , self.tcp_length);
        psh = psh + self.tcp_header + self.user_data;
         
        calulatedcheck = self.checksum(psh)

        if calulatedcheck == self.tcp_check:
            self.correctchecksum = True
            printlog("checksum correct")
        else:
            self.correctchecksum = False
            printlog("checksum incorrect")


    def printPacket(self):
        srcIP = self.source_address
        destIP = self.dest_address

        try:
            srcIP = socket.inet_ntoa(srcIP)
            destIP = socket.inet_ntoa(destIP)
        except:
            pass

        printlog("")
        printlog("source ip: " + str(srcIP))
        printlog("destination ip: " + str(destIP))
        printlog("source port: " + str(self.tcp_source))
        printlog("destination port: " + str(self.tcp_dest))

        printlog("seq: " + str(self.tcp_seq))
        printlog("ack: " + str(self.tcp_ack_seq))
        printlog("data offset: " + str(self.tcp_doff))
        printlog("total length: " + str(self.totlength))

        printlog("fin: " + str(int(self.tcp_fin == True)))
        printlog("syn: " + str(int(self.tcp_syn == True)))
        printlog("rst: " + str(int(self.tcp_rst == True)))
        printlog("psh: " + str(int(self.tcp_psh == True)))
        printlog("ack: " + str(int(self.tcp_ack == True)))
        printlog("urg: " + str(int(self.tcp_urg == True)))

        printlog("window: " + str(self.tcp_window))
        # printlog("checksum:", self.tcp_check
        printlog("urg pointer: " + str(self.tcp_urg_ptr))

        printlog("data: " + str(self.user_data))

        # print ""
        # print "source ip:", srcIP
        # print "destination ip:", destIP
        # print "source port:", self.tcp_source
        # print "destination port:", self.tcp_dest

        # print "seq:", self.tcp_seq
        # print "ack:", self.tcp_ack_seq
        # print "data offset:", self.tcp_doff
        # print "total length:", self.totlength

        # print "fin:", int(self.tcp_fin == True)
        # print "syn:", int(self.tcp_syn == True)
        # print "rst:", int(self.tcp_rst == True)
        # print "psh:", int(self.tcp_psh == True)
        # print "ack:", int(self.tcp_ack == True)
        # print "urg:", int(self.tcp_urg == True)

        # print "window:", self.tcp_window
        # # print "checksum:", self.tcp_check
        # print "urg pointer:", self.tcp_urg_ptr

        # print "data:", self.user_data
        



# if pack("H",1) == "\x00\x01": # big endian
#     def checksum(pkt):
#         if len(pkt) % 2 == 1:
#             pkt += "\0"
#         s = sum(array.array("H", pkt))
#         s = (s >> 16) + (s & 0xffff)
#         s += s >> 16
#         s = ~s
#         return s & 0xffff
# else:
#     def checksum(pkt):
#         if len(pkt) % 2 == 1:
#             pkt += "\0"
#         s = sum(array.array("H", pkt))
#         s = (s >> 16) + (s & 0xffff)
#         s += s >> 16
#         s = ~s
#         return (((s>>8)&0xff)|s<<8) & 0xffff

# def carry_around_add(a, b):
#     c = a + b
#     return (c & 0xffff) + (c >> 16)

# def checksum(msg):    # <- Use this one
#     s = 0
#     for i in range(0, len(msg), 2):
#         w = ord(msg[i]) + (ord(msg[i+1]) << 8)
#         s = carry_around_add(s, w)
#     return ~s & 0xffff

# def checksum(pkt):  # <- This one works too
#     if len(pkt) % 2 == 1:
#         pkt += "\0"
#     s = sum(array.array("H", pkt))
#     s = (s >> 16) + (s & 0xffff)
#     s += s >> 16
#     s = ~s
#     return s & 0xffff

# needed for calculation checksum
# def checksum(msg):
#     s = 0
     
#     # loop taking 2 characters at a time
#     for i in range(0, len(msg), 2):
#         w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
#         s = s + w
     
#     s = (s>>16) + (s & 0xffff);
#     s = s + (s >> 16);
     
#     #complement and mask to 4 byte short
#     s = ~s & 0xffff
     
#     return s
 
debug = False
# debug = True
def printlog(s):
    if debug:
        print s