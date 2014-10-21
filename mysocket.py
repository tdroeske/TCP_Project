import socket, sys, time
from random import randint
from struct import *
import array
 
# Block ICMP: "sudo iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP"  <-- 3 is specific to Port Unreachable message
# Disable RST Packets: "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 72.19.81.206 -j DROP"  <-- Use src IP
# Enable Promiscuous mode: "sudo ifconfig wlan0 promisc"
# Wireshark: ip.dst == 192.241.166.195 or ip.src == 192.241.166.195

class mysocket:

    def __init__(self):
        self.sock = ''
        self.src_ip = '72.19.81.206'
        self.src_port = randint(1024, 65535)
        self.dest_ip = "0.0.0.0"
        self.dest_port = 0
        self.timeout = 0
        self.connOpen = False

        self.currentOutbound = ''
        self.currentInbound = ''

    def accept(self):
        pass

    def bind(self, address):
        pass

    def close(self):
        # send fin packet
        pack = self.currentOutbound
        pack.resetflags()
        pack.tcp_fin = 1;
        pack.tcp_ack = 1;
        pack.user_data = ""
        # pack.createpacket()
        # bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
        # print bytes
        self.__sendpacket(pack)

        # receive ack packet
        # response, addr = self.sock.recvfrom(65535)
        # print len(response)
        # respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        # respPack.extractData(response)
        self.__recvpacket()

        # receive fin packet
        # response, addr = self.sock.recvfrom(65535)
        # print len(response)
        # respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        # respPack.extractData(response)
        self.__recvpacket()

        # send ack packet
        pack = self.currentOutbound
        pack.resetflags()
        pack.tcp_ack = 1
        # pack.createpacket()
        # bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
        self.__sendpacket(pack)

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

        self.__connsetup()

        

    def getpeername(self):
        return self.dest_ip, self.dest_port

    def sockName(self):
        return self.src_ip, self.src_port

    def listen(self, backlog):
        pass

    def recv(self, bufsize):
        # receive push packet
        # response, addr = self.sock.recvfrom(bufsize)
        # print len(response)
        # respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        # respPack.extractData(response)
        # self.currentInbound = respPack
        while 1:
            self.__recvpacket()
            if self.currentInbound.tcp_psh:
                break

        # send ack packet
        # pack = self.currentOutbound
        # pack.tcp_ack_seq += len(self.currentInbound.user_data)
        # pack.resetflags()
        # # pack.tcp_psh = 1
        # pack.tcp_ack = 1
        # # pack.createpacket()
        # # bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
        # self.__sendpacket(pack)
        self.__sendack()
        return self.currentInbound.user_data


    def recvfrom(self, bufsize):
        pass

    def send(self, data):
        # send data with push ack
        pack = self.currentOutbound
        pack.resetflags()
        pack.tcp_psh = 1;
        pack.tcp_ack = 1;
        pack.user_data = data
        # pack.createpacket()
        # bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
        self.__sendpacket(pack)

        # receive ack
        # response, addr = self.sock.recvfrom(65535)
        # print len(response)
        # respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        # respPack.extractData(response)
        self.__recvpacket()

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def __connsetup(self):
        # Send syn packet
        pack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        pack.tcp_syn = 1
        pack.tcp_seq = randint(0, 2**32)
        # pack.createpacket()
        # print self.dest_ip
        # bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
        # print bytes
        self.__sendpacket(pack)

        # Receive syn ack packet
        # response, addr = self.sock.recvfrom(65535)
        # # print len(response)
        # respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        # respPack.extractData(response)
        # # respPack.printPacket()
        self.__recvpacket()
        self.connOpen = True


        # time.sleep(1)


        # send ack packet
        # pack.resetflags()
        # pack.tcp_ack = 1
        # pack.tcp_seq +=1
        # pack.tcp_ack_seq = self.currentInbound.tcp_seq+1
        # # pack.user_data = "Hello World!"
        # # pack.createpacket()
        # # bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
        # # print bytes
        # # self.currentOutbound = pack
        # self.__sendpacket(pack)
        self.__sendack()

    def __sendpacket(self, pack):
        if self.connOpen or pack.tcp_syn:
            pack.createpacket()
            bytes = self.sock.sendto(pack.packet, (self.dest_ip , 0 ))
            self.currentOutbound = pack
            self.currentOutbound.tcp_seq += len(self.currentOutbound.user_data)
            pack.printPacket()

    def __recvpacket(self):
        if self.connOpen or self.currentOutbound.tcp_syn:
            while 1:  
                response, addr = self.sock.recvfrom(65535)
                respPack = packet(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
                respPack.extractData(response)
                if respPack.source_address == self.dest_ip and respPack.dest_address == self.src_ip:
                    break

            self.currentInbound = respPack
            if not self.__validatePacket(respPack):
                # return None
                print ""
                print "invalid packet"
                print ""
            # print len(response)
            # print respPack.user_data
            # self.currentOutbound.tcp_ack_seq += len(self.currentInbound.user_data)
            respPack.printPacket()
            return respPack

    def __validatePacket(self, pack):
        # if fin ack received, close connection
        if self.currentInbound.tcp_fin:
            self.__closeRequested()
            return True

        # if syn sent, expect syn ack
        if self.currentOutbound.tcp_syn:
            return self.currentInbound.tcp_syn and self.currentInbound.tcp_ack

        # if psh ack sent, expect ack
        if self.currentOutbound.tcp_psh and self.currentOutbound.tcp_ack:
            return self.currentInbound.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin

        # if fin ack sent, expect ack
        if self.currentOutbound.tcp_fin and self.currentOutbound.tcp_ack:
            return self.currentInbound.tcp_ack and not self.currentInbound.tcp_psh and not self.currentInbound.tcp_fin

    def __sendack(self):
        # send ack packet
        pack = self.currentOutbound

        if self.currentInbound.tcp_psh:
            pack.tcp_ack_seq += len(self.currentInbound.user_data)

        if self.currentInbound.tcp_syn and self.currentInbound.tcp_ack:
            pack.tcp_seq +=1
            pack.tcp_ack_seq = self.currentInbound.tcp_seq+1

        pack.resetflags()
        pack.tcp_ack = 1
        pack.user_data = ""
        self.__sendpacket(pack)

    def __closeRequested(self):
        # fin ack received
        # send ack packet
        pack = self.currentOutbound
        # pack.resetflags()
        # pack.tcp_ack = 1
        # self.__sendpacket(pack)
        self.__sendack()

        # send fin ack packet
        pack.resetflags()
        pack.tcp_fin = 1;
        pack.tcp_ack = 1;
        pack.user_data = ""
        self.__sendpacket(pack)

        # receive ack packet
        self.__recvpacket()

        self.connOpen = False

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
        self.tcp_window = socket.htons (5840)    #   maximum allowed window size
        self.tcp_check = 0
        self.tcp_urg_ptr = 0

        # pseudo header fields
        self.source_address = socket.inet_aton( source_ip )
        self.dest_address = socket.inet_aton(dest_ip)
        self.placeholder = 0
        self.protocol = socket.IPPROTO_TCP

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
        print ""



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
 