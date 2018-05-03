import socket
import struct
import time

UDP_IP = ""
UDP_PORT = 4445

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

#data format is 1 int (packet number), 11 bytes (data), 5 signed long long (times)
dform = ">i940b6q"

f = open("profile_results.csv", mode='w')

f.write("pid,profiletx,udpr1,udpx1,ponger,udpr2,udpx2,profilerx\n")
counter = 0
while True:
    data, addr = sock.recvfrom(1024)
    unpacked = struct.unpack(dform, data)
    f.write("{},{},{},{},{},{},{},{}\n".format(unpacked[0],unpacked[941],unpacked[942],unpacked[943],unpacked[944],unpacked[945],unpacked[946],(time.time() * 1000000000)))
    counter = counter + 1
    if counter > 10:
        break
f.close()
    
