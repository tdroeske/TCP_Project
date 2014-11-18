import socket, sys, time
from random import randint
from struct import *
import array
import threading
import Queue
import copy
 
# Block ICMP: "sudo iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP"  <-- 3 is specific to Port Unreachable message
# Disable RST Packets: "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 72.19.82.224 -j DROP"  <-- Use src IP
# Enable Promiscuous mode: "sudo ifconfig wlan0 promisc"
# Wireshark: ip.dst == 192.241.166.195 or ip.src == 192.241.166.195

class mysocket:

    def __init__(self):
        self.sock = ''
        self.src_ip = '72.19.82.224'
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
        self.sendBase = 0; # Oldest unacknowledged byte
        self.nextseqnum = 0;
        self.nextseqnumsent = 0;
        self.nextacknum = 0;
        # self.recvthread.start()
        # time.sleep(1)
        # self.src_ip = '192.168.1.1'

        self.inboundrecvwin = 0     # TODO change these accordingly and add in checks
        self.outboundrecvwin = 0

        self.printlock = threading.Lock()
        # self.sendlock = threading.Lock()

    def accept(self):
        pass

    def bind(self, address):
        pass

    def close(self):
        self.threadsOpen = False

        # send fin packet
        pack = self.currentOutbound
        pack.resetflags()
        pack.tcp_fin = 1;
        pack.tcp_ack = 1;
        pack.user_data = ""
        self.__sendpacket(pack)

        # receive ack packet
        self.__recvpacket()

        # receive fin packet
        self.__recvpacket()

        # send ack packet
        # pack = self.currentOutbound
        # pack.resetflags()
        # pack.tcp_ack = 1
        # pack.tcp_seq += 1
        # pack.tcp_ack_seq += 1
        # self.__sendpacket(pack)

        self.connOpen = False

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
        pass

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
                data = self.recvQueue.pop(0).user_data
                # self.recvstart += 1
                self.recvend -= 1
                return data
            # else:
            #     printlog("no data to receive")


    def recvfrom(self, bufsize):
        pass

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
                if respPack.source_address == self.dest_ip and respPack.dest_address == self.src_ip:
                    self.__printPacket(respPack)
                    break

            self.currentInbound = respPack
            if not self.__validatePacket(respPack):
                pass
                # return None
                # print ""
                # print "invalid packet"
                # print ""
            # print len(response)
            # print respPack.user_data
            # self.currentOutbound.tcp_ack_seq += len(self.currentInbound.user_data)
            return respPack

    def __validatePacket(self, pack):

        if pack.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin:
            self.__ackrecvd(pack) 

        # if fin ack received, close connection
        if self.currentInbound.tcp_fin:
            self.__finrecvd()
            return True

        # if syn sent, expect syn ack
        if self.currentOutbound.tcp_syn:
            # print "invalid packet: syn sent, expected syn ack"
            return self.currentInbound.tcp_syn and self.currentInbound.tcp_ack

        # if psh ack sent, expect ack
        # if self.currentOutbound.tcp_psh and self.currentOutbound.tcp_ack:
        #     print "invalid packet: psh ack sent, expected ack"
        #     return self.currentInbound.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin

        # if fin ack sent, expect ack
        if self.currentOutbound.tcp_fin and self.currentOutbound.tcp_ack:
            # print "invalid packet: fin ack sent, expected ack"
            return self.currentInbound.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin

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
            pack.tcp_ack_seq = self.currentInbound.tcp_seq+1

        pack.resetflags()
        pack.tcp_ack = 1
        pack.user_data = ""
        self.__sendpacket(pack)

    def __ackrecvd(self, pack):
        if pack.tcp_ack_seq > self.sendBase:
            self.sendBase = pack.tcp_ack_seq
            '''
            if (there are currently any not-yet-acknowledged segments)
                start timer
            }
            '''
        # for p in  self.outboundQueue:
            # if p.tcp_seq < pack.tcp_ack_seq:
                # remove from queue


    def __finrecvd(self):
        print "Fin received"
        # fin ack received
        pack = self.currentOutbound
        inpack = self.currentInbound
        # pack.resetflags()
        # pack.tcp_ack = 1
        # self.__sendpacket(pack)

        self.__sendack()
        self.threadsOpen = False
        # if we didn't initiate the close connection, then respond with an ack, then a fin ack
        if not pack.tcp_fin:
            # send ack packet
            # pack.resetflags()
            # pack.tcp_ack = 1
            # pack.tcp_seq += 1
            # pack.tcp_ack_seq = inpack.tcp_seq + 1
            # print "Acking the unexpected Fin Ack"
            # self.__sendack()


            # send fin ack packet
            pack.resetflags()
            pack.tcp_fin = 1;
            pack.tcp_ack = 1;
            pack.user_data = ""
            self.__sendpacket(pack)

            # receive ack packet
            self.__recvpacket()

            self.connOpen = False

    def __calculatetimeout(self, sampleRTT):
        self.estimatedRTT = 0.875 * self.estimatedRTT + 0.125 * sampleRTT   # pg. 239
        self.devRTT = 0.75 * self.devRTT + 0.25 * abs(sampleRTT - self.estimatedRTT)     # pg. 240
        self.timeoutinterval = self.estimatedRTT + 4 * self.devRTT


    def __recvloop(self):
        # print "Testing thread"
        # print self.src_ip
        # time.sleep(3)
        # print self.src_ip
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
                    if self.currentInbound.tcp_seq < self.nextacknum:
                            seen = True
                    if not seen:
                        self.recvQueue.append(self.currentInbound)
                        printlog("Added packet to recvQueue")
                        if self.currentInbound.tcp_seq == self.nextacknum:
                            self.recvend += 1 # TODO this needs to be incremented to the 1 after the last in-order packet, not always 1, use while loop
                            printlog("recvend incremented")
                        else:
                            printlog("Out of order packet")
                        self.nextacknum = self.currentInbound.tcp_seq + len(self.currentInbound.user_data)
                    else:
                        printlog("Duplicate packet received")

                    self.__sendack()
                    
                else:
                    print "Not a psh packet"
            except:
                pass
        self.sock.setblocking(1)
        printlog("recvloop done")

    def __sendloop(self):
        while self.threadsOpen:
            if not len(self.sendQueue) == 0:
                pack = self.sendQueue.pop(0)
                if pack.tcp_psh:
                    self.outboundQueue.append(pack)
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
        self.source_address = socket.inet_aton( source_ip )
        self.dest_address = socket.inet_aton(dest_ip)
        self.placeholder = 0
        self.protocol = socket.IPPROTO_TCP

        self.timesent = 0

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
         
        self.tcp_check = checksum(psh)

        self.packet = self.makeTCPheader() + self.user_data

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

    def printPacket(self):
        srcIP = self.source_address
        destIP = self.dest_address

        try:
            srcIP = socket.inet_ntoa(srcIP)
            destIP = socket.inet_ntoa(destIP)
        except:
            pass

        print ""
        print "source ip:", srcIP
        print "destination ip:", destIP
        print "source port:", self.tcp_source
        print "destination port:", self.tcp_dest

        print "seq:", self.tcp_seq
        print "ack:", self.tcp_ack_seq
        print "data offset:", self.tcp_doff
        print "total length:", self.totlength

        print "fin:", int(self.tcp_fin == True)
        print "syn:", int(self.tcp_syn == True)
        print "rst:", int(self.tcp_rst == True)
        print "psh:", int(self.tcp_psh == True)
        print "ack:", int(self.tcp_ack == True)
        print "urg:", int(self.tcp_urg == True)

        print "window:", self.tcp_window
        # print "checksum:", self.tcp_check
        print "urg pointer:", self.tcp_urg_ptr

        print "data:", self.user_data
        



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

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

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
 
debug = True
def printlog(s):
    if debug:
        print s