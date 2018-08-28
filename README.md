# udp_rx
This is still currently pre-1.0 software, breaking changes are likely to be made until a 1.0 release

udp_rx is a program created to tunnel udp traffic through a TLS 1.3 connection. It is useful for securing old protocols that cannot be updated to tcp or for some reason, can't use dtls. If you use this tool you _should_ firewall off the udp ports used by the protocol to prevent redirection by a malicious third party and _should_ firewall off the UDP port used by udp_rx.

Please see gen_keys_readme.txt for creating/using SSL keys with udp_rx

Please see IPTABLES_RULE.txt for a sample IPTABLES command to firewall off a port protected by udp_rx

## Export Control Notice
Otis udp_rx software has been designed to utilize information security technology described in the Category 5 – Part 2 of the Commerce Control List, within Part 774 of the Export Administration Regulations (“EAR”)(15 CFR 774).  However, the Otis udp_rx software has been made publicly available in accordance with Part 742.15(b) of the EAR and is therefore not subject to U.S. export regulations. 

Before downloading this software, be aware that the country in which you are located may have restrictions related to the import, download, possession, use and/or reexport of encryption items.  It is your responsibility to comply with any applicable laws and regulations pertaining the import, download, possession, use and/or reexport of encryption items.

## How to use it
You have a UDP packet that you want to be sent to `192.168.1.250` with a destination port of of `4444`. The data field of that packet is 

```[10,9,8,7,6,5,4,3,2,1]```

Take that packet and prepent the ip address and port to the data field (`4444` == `[11,92]` (big endian)).

```[192,168,1,250,11,92,10,9,8,7,6,5,4,3,2,1]```

Send that packet to `localhost:55555` (or whatever port udp_rx is configured to listen to)

udp_rx will attempt to create a tls connection to another instance of udp_rx running on `192.168.1.250`. If it succeeds:

udp_rx will recieve the packet and perform two different actions depending on platform.

### Linux
udp_rx will recieve the packet and craft a udp packet from `sender:src_port` to `destination:dest_port` as if udp_rx was never in the middle, so that it can be recieved by the desination application.

### Windows
udp_rx will recieve the packet and create a udp packet from `localhost:random_port` to `desination:dest_port`. It will prepend the sender's IP address and src_port to the data. So if the sender was `192.168.1.100`, from port `4445` the packet data field would be:

```[192,168,1,100,11,93,10,9,8,7,6,5,4,3,2,1]```

## License
This program is released under the MIT License. For details, please see the LICENSE file

## Credits
This program uses the following open source libraries
* [logrus](https://github.com/sirupsen/logrus) - Copyright Simon Eskildsen (MIT License)
* [lumberjack](https://github.com/natefinch/lumberjack/tree/v2.1) - Copyright Nate Finch (MIT License)

---

Copyright 2018, Otis Elevator Company