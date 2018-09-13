// Copyright 2018 Otis Elevator Company. All rights reserved.
// Use of this source code is govered by the MIT license which
// can be found in the LICENSE file.

// Author: Jeremy Mill: jeremy.mill@otis.com

// Otis udp_rx software has been designed to utilize information
// security technology described in the Category 5 – Part 2 of the
// Commerce Control List, within Part 774 of the Export Administration
// Regulations (“EAR”)(15 CFR 774).  However, the Otis udp_rx software
// has been made publicly available in accordance with Part 742.15(b)
// of the EAR and is therefore not subject to U.S. export regulations.
// Before downloading this software, be aware that the country in which
// you are located may have restrictions related to the import, download,
// possession, use and/or reexport of encryption items.  It is your
// responsibility to comply with any applicable laws and regulations
// pertaining the import, download, possession, use and/or reexport of
// encryption items.
package udprxlib

import (
	"testing"
)

func TestIPChecksum(t *testing.T) {
	ip := Iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: 0x11,
	}
	ip.Checksum()
	if ip.csum != 0 {
		t.Error("non zero checksum")
	}
}

func TestUDPChecksum(t *testing.T) {
	ip := Iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: 0x11,
	}
	udp := Udphdr{
		src: uint16(1),
		dst: uint16(2),
	}
	udp.Checksum(&ip, []byte{1, 2, 3, 4, 5})
	if udp.csum != 0 {
		t.Error("non zero checksum")
	}
}

func TestParseIpSuccess(t *testing.T) {
	ip1, ip2, err := ParseIps("192.168.1.1", "191.168.1.10")
	if err != nil {
		t.Error("Error parsing good ip addresses")
	}
	if ip1.To4()[0] != 192 {
		t.Error("error with msb of ip 1")
	}
	if ip2.To4()[0] != 191 {
		t.Error("error with msb of ip 2")
	}
}

func TestParseIpFail(t *testing.T) {
	_, _, err := ParseIps("192.168.1", "191.168.1.10")
	if err == nil {
		t.Error("ip 1 should have failed")
	}
}
func TestParseIpFail2(t *testing.T) {
	_, _, err := ParseIps("192.168.1.250", "191.168.1")
	if err == nil {
		t.Error("ip 2 should have failed")
	}
}
