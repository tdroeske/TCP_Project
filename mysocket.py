import socket, sys
from struct import *
 

class mysocket:

    def __init__(self):
        self.src_ip = '128.119.73.255'
        self.src_port = 1234
        self.dest_ip = "0.0.0.0"
        self.dest_ip = 0
        self.timeout = 0

    def accept(self):
        pass

    def bind(self, address):
        pass

    def close(self):
        pass

    def connect(self, address):
        pass

    def getpeername(self):
        return self.dest_ip, self.dest_port

    def sockName(self):
        return self.src_ip, self.src_port

    def listen(self, backlog):
        pass

    def recv(self, bufsize):
        data = self.recvfrom(bufsize)
        return data

    def recvfrom(self, bufsize):
        pass

    def send(self, date):
        pass

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

class packet:

    def __init__(self):
        self.ip_header = ""
        self.tcp_header = ""
        self.data = ""

        # ip header fields
        self.ip_ihl = 5
        self.ip_ver = 4
        self.ip_tos = 0
        self.ip_tot_len = 0  # kernel will fill the correct total length
        self.ip_id = 54321   #Id of this packet
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_check = 0    # kernel will fill the correct checksum
        self.ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
        self.ip_daddr = socket.inet_aton ( dest_ip )
        
        self.ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # tcp header fields
        self.tcp_source = 1234   # source port
        self.tcp_dest = 12000   # destination port
        self.tcp_seq = 454
        self.tcp_ack_seq = 0
        self.tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        self.tcp_fin = 0
        self.tcp_syn = 1
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        self.tcp_window = socket.htons (5840)    #   maximum allowed window size
        self.tcp_check = 0
        self.tcp_urg_ptr = 0
         
        self.tcp_offset_res = (tcp_doff << 4) + 0
        self.tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

        # pseudo header fields
        self.source_address = socket.inet_aton( source_ip )
        self.dest_address = socket.inet_aton(dest_ip)
        self.placeholder = 0
        self.protocol = socket.IPPROTO_TCP
        self.tcp_length = len(tcp_header) + len(user_data)

    def makeIPheader(self):
        # the ! in the pack format string means network order
        self.ip_header = pack('!BBHHHBBH4s4s' , self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_frag_off, self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)
        return self.ip_header

    def makeTCPheader(self):
        # the ! in the pack format string means network order
        # checksum is NOT in network byte order
        self.tcp_header = pack('!HHLLBBH' , self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, self.tcp_offset_res, self.tcp_flags,  self.tcp_window) + pack('H' , self.tcp_check) + pack('!H' , self.tcp_urg_ptr)
        return self.tcp_header

    def createpacket(self):
        self.makeTCPheader()
        self.tcp_length = len(self.tcp_header) + len(self.user_data)

        psh = pack('!4s4sBBH' , self.source_address , self.dest_address , self.placeholder , self.protocol , self.tcp_length);
        psh = psh + tcp_header + user_data;
         
        self.tcp_check = checksum(psh)

        return self.makeIPheader() + self.makeTCPheader() + self.data

# needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s
 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
     
# now start constructing the packet
packet = '';
 
source_ip = '128.119.74.85'
dest_ip = '192.241.166.195'
 
# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ip )
 
ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
 
# tcp header fields
tcp_source = 1234   # source port
tcp_dest = 12000   # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0
 
tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
 
user_data = 'Hello, how are you'
 
# pseudo header fields
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)
 
psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
psh = psh + tcp_header + user_data;
 
tcp_check = checksum(psh)
tcp_check = checksum(tcp_header + user_data)
#print tcp_checksum
 
# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
# final full packet - syn packets dont have any data
packet = ip_header + tcp_header + user_data
 
#Send the packet finally - the port specified has no effect
bytes = s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target
print bytes