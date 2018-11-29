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

'''This script is for testing udp_rx transmit side functionality
including a "good" and a "bad" IP address'''
import struct
import socket

HEADER_VERSION = bytes([0x01, 0x00, 0x00])

IP = bytes([192,168,56,1])
IP_FROM = bytes([192,168,56,102])

PORT = struct.pack(">I", 50300)[2:]

DATA = bytes([5,4,3,2,1])
HEADER_NO_SENDER = bytes([0x75]) + HEADER_VERSION + PORT + bytes([0x04]) + IP + bytes([0x80])
HEADER_SENDER = bytes([0x75]) + HEADER_VERSION + PORT + bytes([0x04]) + IP + bytes([0x76]) + IP_FROM + bytes([0x80])


PACKET_NO_SENDER = HEADER_NO_SENDER + DATA
PACKET_SENDER = HEADER_SENDER + DATA
DEST = "127.0.0.1"
DEST_PORT = 55555
SOCK = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
for _ in range(0,1):
    SOCK.sendto(PACKET_NO_SENDER, (DEST, DEST_PORT))
for _ in range(0,1):
    SOCK.sendto(PACKET_SENDER, (DEST, DEST_PORT))
