import struct
import socket

IP = bytes([172,28,237,9])
PORT = struct.pack(">I", 50300)[2:]

DATA_GOOD = bytes([10,9,8,7,6,5,4,3,2,1,0])
DATA_BAD = bytes([-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,])

PACKET_GOOD = (IP + PORT + DATA_GOOD)
PACKET_BAD = (IP + PORT + DATA_BAD)

DEST = "127.0.0.1"
DEST_PORT = 55555
SOCK = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP


for _ in range(0,10):
    SOCK.sendto(PACKET_GOOD, (DEST, DEST_PORT))
    SOCK.sendto(PACKET_BAD, (DEST, DEST_PORT))