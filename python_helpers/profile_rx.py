# Copyright 2018 Otis Elevator Company. All rights reserved.
# Use of this source code is govered by the MIT license which
# can be found in the LICENSE file.

# Author: Jeremy Mill: jeremy.mill@otis.com

# Otis udp_rx software has been designed to utilize information
# security technology described Part 774 of the EAR Category 5 Part 2
# but has been made publicly available in accordance with Part 742.15(b)
# and is therefore not subject to U.S. export regulations.
# Before you download this software be aware that the country in which you
# are located may have restrictions related to the import, possession, use
# and/or reexport of encryption items.  It is your responsibility to comply
# with any applicable laws and regulations pertaining the import, possession,
# use and/or reexport of encryption items.

'''This script is for testing udp_rx receive side network pofiling testing'''

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
    
