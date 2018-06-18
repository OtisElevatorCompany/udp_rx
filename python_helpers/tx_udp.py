import struct
import socket

IP = bytes([172,27,204,154])
IP_BAD = bytes([172,28,237,2])
#gets the bottom 2 bytes of this 'struct' which is 50300 to 2 bytes
PORT = struct.pack(">I", 50300)[2:]

#junk data
DATA = bytes([10,9,8,7,6,5,4,3,2,1,0])

#combine into one packet
PACKET_CONTENTS = (IP + PORT + DATA)
BAD_PACKET_CONTENTS = (IP_BAD + PORT + DATA)

DEST = "127.0.0.1"
DEST_PORT = 55555
SOCK = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
for _ in range(0,10000):
    SOCK.sendto(PACKET_CONTENTS, (DEST, DEST_PORT))
for _ in range(0,100):
    SOCK.sendto(BAD_PACKET_CONTENTS, (DEST, DEST_PORT))
for _ in range(0,100):
    SOCK.sendto(PACKET_CONTENTS, (DEST, DEST_PORT))
