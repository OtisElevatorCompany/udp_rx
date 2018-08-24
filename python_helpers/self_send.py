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

'''This script is for testing udp_rx self-send functionality which should skip the TLS step
and send directly to the local IP'''

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
