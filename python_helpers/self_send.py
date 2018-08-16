import struct
import socket

IP = bytes([192,48,97,150])
#IP = bytes([127,0,0,1])
PORT = struct.pack(">I", 50300)[2:]
#junk data
DATA = bytes([10,9,8,7,6,5,4,3,2,1,0])
#combine
PACKET_CONTENTS = (IP + PORT + DATA)

DEST = "127.0.0.1"
DEST_PORT = 55555
SOCK = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
for _ in range(0,1):
    SOCK.sendto(PACKET_CONTENTS, (DEST, DEST_PORT))
