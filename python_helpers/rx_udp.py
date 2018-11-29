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

'''This script is for testing udp_rx recieve side functionality'''

import socket
import os

UDP_IP = "192.168.56.1"
UDP_PORT = 50300

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("python - sockets built\n")
counter = 0
while True:
    print("python - awaiting new connection...")
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    counter += 1
    #print("python - ", counter)
    if os.name == 'nt':
        ip = data[0:4]
        port = data[4:6]
        data = data[6:]
        ipstring = ''
        for octet in ip:
            ipstring = ipstring + str(octet) + "."
        port = (port[0] << 8) + port[1]
        print("IP: ", ipstring)
        print("port: ", port)
        print("data: ", data)
    else:
        print("received message: {}\tfrom: {}".format(data, addr))
