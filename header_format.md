# udp_rx Header Format

## Description
udp_rx supports IPv4 and IPv6 and has a variable length header to accommodate the different lengths in addressing. udp_rx also supports multiple IP addresses assigned to a single adapter. To support this, a 'sender' IP address can be added to the header to force udp_rx to use that IP address as the sending IP.

## Format

| Byte           | Description                                            | Accepted Values                                    |
|----------------|--------------------------------------------------------|----------------------------------------------------|
| 0              | Magic Number                                           | 0x75                                               |
| 1              | Major Version                                          | 0-255                                              |
| 2              | Minor Version                                          | 0-255                                              |
| 3              | Patch Version                                          | 0-255                                              |
| 4              | Destination Port Upper Byte (big endian)               | 0-255                                              |
| 5              | Destination Port Lower Byte (big endian)               | 0-255                                              |
| B6             | IP Version                                             | 0x04 or 0x06                                       |
| 7-10 or 7-22   | Destination IP address (4 bytes for IPv4, 16 for IPv6) | 0-255                                              |
| 11 or 23       | End or Source IP flag                                  | 0x80 for end of header, 0x76 for Source IP follows |
| 12-15 or 24-39 | Source IP address (optional)                           | 0-255                                              |
| 16 or 40       | End Magic Header                                       | 0x80                                               |

## Examples
Sample version 0.1.19 IPv4 Header packet being send to 192.168.1.250 on port 50300 with no source IP info

`0x75| 0x00| 0x01| 0x13| 0xc4 | 0x7c | 0x04 | 0xC0 | 0xa8 | 0x01 | 0xFA | 0x80`

Sample version 0.1.19 IPv4 Header packet being send to 192.168.1.250 on port 50300 from 192.168.1.100


`0x75| 0x00| 0x01| 0x13| 0xc4 | 0x7c | 0x04 | 0xC0 | 0xa8 | 0x01 | 0xFA | 0x80 | 0xC0 | 0xa8 | 0x01 | 0x64 | 0x80`
