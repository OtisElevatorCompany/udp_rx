# udp_rx
This is still currently pre-1.0 software, breaking changes are likely to be made until a 1.0 release

udp_rx is a program created to tunnel UDP traffic through a TLS 1.2+ connection. It is useful for securing old protocols that cannot be updated to tcp or for some reason, can't use dtls. If you use this tool you **should** firewall off the UDP ports used by the protocol to prevent redirection by a malicious third party and **should** firewall off the UDP port used by udp_rx.

Please see gen_keys_readme.txt for creating/using SSL keys with udp_rx

Please see IPTABLES_RULE.txt for a sample IPTABLES command to firewall off a port protected by udp_rx

## Export Control Notice
Otis udp_rx software has been designed to utilize information security technology described in the Category 5 – Part 2 of the Commerce Control List, within Part 774 of the Export Administration Regulations (“EAR”)(15 CFR 774).  However, the Otis udp_rx software has been made publicly available in accordance with Part 742.15(b) of the EAR and is therefore not subject to U.S. export regulations. 

Before downloading this software, be aware that the country in which you are located may have restrictions related to the import, download, possession, use and/or reexport of encryption items.  It is your responsibility to comply with any applicable laws and regulations pertaining the import, download, possession, use and/or reexport of encryption items.

## How to use it
You have a UDP packet that you want to be sent to `192.168.1.250` with a destination port of `4444`. The data field of that packet is 

`[5,4,3,2,1]`

Take that packet and prepend a udp_rx header to it according to the specification in `header_format.md`. In this case the header would look like:

`[0x75,0x00,0x01,0x13,0xc4,0x7c,0x04,0xC0,0xa8,0x01,0xFA,0x80]`

and the resulting packet would be:

`[0x75,0x00,0x01,0x13,0x11,0x5c,0x04,0xC0,0xa8,0x01,0xFA,0x80,5,4,3,2,1]`

Send that packet to `localhost:55555` (or whatever port udp_rx is configured to listen to)

udp_rx will attempt to create a TLS connection to another instance of udp_rx running on `192.168.1.250`. If it succeeds:

udp_rx will receive the packet and perform two different actions depending on platform.

### Linux
udp_rx will receive the packet and craft a UDP packet from `sender:src_port` to `destination:dest_port` as if udp_rx was never in the middle, so that it can be received by the desination application.

### Windows
udp_rx will receive the packet and create a UDP packet from `localhost:random_port` to `desination:dest_port`. It will prepend the sender's IP address and src_port to the data. So if the sender was `192.168.1.100`, from port `4445` the packet data field would be:

```[192,168,1,100,11,5D,10,9,8,7,6,5,4,3,2,1]```

## License
This program is released under the MIT License. For details, please see the LICENSE file

## Building
Please see `BUILD.md` for instructions on building udp_rx.

## Credits
This program uses the following open source libraries
* [logrus](https://github.com/sirupsen/logrus) - Copyright Simon Eskildsen (MIT License)
* [lumberjack](https://github.com/natefinch/lumberjack/tree/v2.1) - Copyright Nate Finch (MIT License)

---

Copyright 2018, Otis Elevator Company