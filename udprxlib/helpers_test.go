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

import "testing"

func TestIntToBytes(t *testing.T) {
	bytes := intToBytes(1)
	if bytes[0] != 0 {
		t.Error("wrong byte order")
	}
}
func TestIntoToBytesFull(t *testing.T) {
	bytes := intToBytes(1025)
	if bytes[0] != 0x04 {
		t.Error("wrong byte order or wrong value")
	}
	if bytes[1] != 0x01 {
		t.Error("Wrong lower side")
	}
}

func TestGetTimeBytes(t *testing.T) {
	getTime = returnTime
	timeBytes := getTimeBytes()
	goodtimeBytes := []byte{17, 116, 239, 237, 171, 24, 96, 0}
	for index := range timeBytes {
		if timeBytes[index] != goodtimeBytes[index] {
			t.Error("Wrong Time")
		}
	}
}
func returnTime() int64 {
	return 1257894000000000000
}
